---
name: project-outlet-streaming-manifest-frontier
description: Outlet-streaming §5.4.5 manifest/billing seam facts — MerkleFrontier vs oracle, OutletInvokedEvent has no cancel_ack_seq, EventType::OutletInvoked payload is overloaded
metadata:
  type: project
---

Non-obvious facts for §5.4.5 outlet-streaming manifest + `chunks_billed` work (ADR-061). Established while implementing C5 (incremental frontier) + C1 (append wire-invariant), commit e6fdf8b1b on `feat/outlet-streaming-ffi`.

**MerkleFrontier == batch oracle.** `scp-protocol/src/context/outlets/stream.rs` has `compute_chunk_manifest_root` (batch, level-by-level pair-and-promote) AND now `MerkleFrontier` (incremental forest-of-perfect-subtrees, O(log n)). BOTH equal the RFC-6962 §2.1 MTH, hence each other, for ALL n (proven by a proptest asserting frontier.root()==oracle at every prefix). **Keep `compute_chunk_manifest_root` — it is the auditor's re-derivation oracle, not dead code.**

**Two pumps, one event builder.** The OUTER dispatch pump (`dispatch.rs run_stream_pump_v2`) renumbers+re-signs chunks under the outer seq; the INNER `invoke.rs` capture pump (`pump_payload_stream_capture`) is a raw no-gate capture used by manager-direct/test callers. Both now feed a `MerkleFrontier` + `StreamTerminalSummary` via shared `invoke::ingest_stream_chunk`; both stopped retaining a `Vec<OutletStreamChunk>`. `build_streaming_outlet_event` takes precomputed (count, billed, root, terminal_summary) — NOT `&[chunks]`.

**Pump never bills above-cancel-ack.** The dispatch gate returns `DropAboveCancelAck`/`CreditExhausted` BEFORE push, so every emitted Data chunk is at/below the eventual `cancel_ack_seq`. Hence `MerkleFrontier::new()` (unbounded ceiling) at the pump gives the same billed count as `compute_chunks_billed_ref(manifest, cancel_ack_seq)`. `MerkleFrontier::with_ceiling` exists only for the property test (arbitrary sequences with above-ceiling chunks).

**`OutletInvokedEvent` carries NO cancel_ack_seq.** `StreamTerminalStatus::Cancelled` (scp-protocol stream.rs) is a bare unit variant. So the event-log appender, holding only the event, CANNOT re-derive `chunks_billed_ref` (needs the chunk sequence AND cancel_ack_seq). The ONLY event-local wire-invariant is `chunks_billed <= stream_chunk_count` (`verify_outlet_invoked_event_local` in scp-runtime stream.rs). Do not claim to "re-derive from the manifest" at append — be honest.

**`EventType::OutletInvoked` payload is OVERLOADED.** The unary saga (`actor/handlers/saga.rs`) appends a JSON join-record `{saga_id, outlet_invoked_event_id, caller_context_id, ...}` — NOT an `OutletInvokedEvent` (no request_id/chunks_billed). The streaming path (planned) appends the typed `OutletInvokedEvent`. The C1 append check in `MerkleEventLogProvider::append_event` distinguishes by attempting `serde_json::from_slice::<OutletInvokedEvent>` — the saga join-record fails to decode (missing required fields) and passes through unchecked. `append_context_event_with_payload` DELEGATES to `append_event`, so `append_event` is the single choke point. **Assumes JSON encoding at the boundary (matches saga.rs); an rmp-encoded future event would silently skip the check.**

**Streaming OutletInvokedEvent sink is NOT yet wired to production** — only test sinks (`OutletInvokedEventSink` has no prod impl; the pump passes `None`). Production `stream_manifest_hash` sites still hardcode `[0u8;32]` per ADR-061 consequences; the streaming saga is the wiring target. C1 at the provider is the durable backstop for whenever that lands.

**scp-event-log stays runtime-independent** — it owns `EventLogError::ChunksBilledMismatch` (the variant) but the CHECK lives in scp-runtime (`verify_outlet_invoked_event_local`); scp-event-log has no scp-protocol/scp-runtime dep. Runtime constructs the pub error variant + maps via `chunks_billed_error_to_event_log_error`.
