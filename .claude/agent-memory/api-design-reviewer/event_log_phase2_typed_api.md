---
name: event-log-phase2-typed-api
description: Phase-2 event-log typed API surface review (ContextEventLogProvider, EventType, payload structs, event_type_label) — APPROVED round 6
metadata:
  type: project
---

ADR-011 native↔WASM event-log unification — Phase-2 typed API surface. Branch HEAD ccf70dc50, diff 1c0ccbc7d..HEAD. Round-6 confirmation review = APPROVE, no findings.

**Why:** Finding [[finding_runtime_eventlog_not_rfc6962]] — runtime event log had diverged into a stringly-named hash-CHAIN (`EventLogEntry{event:String, payload:Option<JSON>, hash}`, `compute_entry_hash` with `SCP-EXPORT-ENTRY:` preimage). Alec chose FULL unification onto `scp_event_log::EventLog` (RFC 6962 tree).

**API surface as built (all clean):**
- `ContextEventLogProvider::append_event(ctx, event_type: scp_event_log::EventType, actor_did: &str, payload: EventPayload)` — typed enum replaces the old `event: &str` name. Default methods `append_context_event` (no payload) and `append_context_event_with_payload` layer on top; `event_log_entries` is the symmetric read side.
- `EventType` is a CLOSED 76-variant enum, no catch-all. Pinned by `event_type_taxonomy_is_closed_at_76_distinct_variants` test.
- `scp_event_log::payload` module: per-variant payload structs + `encode_payload`/`decode_payload` (positional MessagePack, field order = wire contract). 10 typed structs. Single source of leaf-preimage bytes shared native↔WASM.
- FFI `scp_ffi_common::event_log::event_type_label(&EventType) -> String` (Debug form) is the SINGLE source of truth for the surfaced `event_type` string AND the filter equality clause — lock-step by construction. All 3 bridges (PyO3/NAPI/UniFFI) call it; verified identical shape.
- `Option<EventType>` decoupling (messaging_helpers `deliver_plaintext_or_announcement`, `run_buffered_post_delivery`): `None` = "do NOT append to durable Merkle log" (received app messages are receiver-minted, not sender-authenticated → §9.9.3 equivocation false-positive risk). Clean use of Option to encode a security invariant in the type rather than a sentinel event name. GOOD.

**Misuse-resistance wins:** legacy `EventLogEntry`, `compute_entry_hash`, public `entry_hash` fully deleted (0 residual refs). consequence.rs `payload_target_did` dropped the null-terminated-string legacy fallback; now accepts exactly 2 live encodings (positional MessagePack fixarray elem 0, or JSON `target_did`), both documented against `encode_payload`. Private fns, internal to consequence engine.

`push_leaf_raw` correctly `#[doc(hidden)]` with logical-safety doc. `with_log` proof seam avoids a second tree to keep in sync.
