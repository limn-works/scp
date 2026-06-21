---
name: eventlog-unification-adr011
description: ADR-011 amendment native↔WASM↔FFI event-log single-model unification — durable architecture, the deferred emit-site boundary, and the dead app_sandbox formatters
metadata:
  type: project
---

ADR-011 amendment (`.docs/adrs/phase-2.md`) unifies the runtime, protocol substrate, and WASM event logs onto ONE model: `scp_event_log::EventLog` (RFC 6962 tree, leaf preimage `SHA-256(0x00 ‖ rmp_serde(Event))`).

**Why:** runtime ContextManager event log previously diverged — a hash-CHAIN with `SCP-EXPORT-ENTRY:` format strings + ~18 untyped event names baked into the event NAME (`format!("ContextTombstoned:{dest}")` or a JSON blob as the type tag). This broke native↔WASM equivocation detection (§9.9.3 false positives) and blocked SCP-1535. Alec chose FULL unification 2026-06-17.

**How to apply (durable architecture — APPROVED round 6):**
- `MerkleEventLogProvider` (crates/scp-runtime/src/context/providers/event_log.rs) wraps `scp_event_log::EventLog` directly. NO second tree.
- Single proof seam: `with_log()` gives proof helpers read access to the provider's OWN canonical tree. The `ContextEventLogProvider` trait default `rebuild_event_log_for_proof` (builder.rs:384) replays entries through `tree::append_unsigned_event` → byte-identical tree → identical proofs. Concrete provider overrides to skip the replay. Provably equivalent.
- Trait seam is typed-everywhere: `append_event(context_id, EventType, actor_did, EventPayload)`. NO string-name overload exists on the trait.
- EventType taxonomy is a CLOSED 76-variant enum; tags 0-35 are frozen wire constants, 36-75 are the unification variants. `event_type_tag` is exhaustive; tests assert all-distinct + frozen-0-35 (tree.rs).
- Typed payloads in `scp_event_log::payload` use POSITIONAL rmp_serde (fixarray, not named map) — field order is wire contract. Tests assert fixarray marker + arity.
- Consequence engine (consequence.rs) reads `target_did` from BOTH typed positional-MessagePack (rmp_array_first_string) AND legacy JSON-object — bounded dual-decoder, two shapes only, not an open parser. `event_log_entries_for_consequences` (governance_logic.rs:669) projects the typed taxonomy onto coarse trigger buckets via one exhaustive match; folds consequence variants into GovernanceAction (closes white-hat H4 recursive blind-spot).

**Deferred emit-site boundary (#A) — SAFE & scoped:** Phase 1 establishes the TYPES + payload structs + decoders. Production emit sites for some variants land later. The payload.rs docstring states this explicitly. Boundary is safe because: (a) consequence decoder handles both encodings, (b) no live emit path pushes a name-string into `payload` where a typed decoder would misread it.

**FINDING (non-blocking, durability nit):** `app_sandbox.rs:854 format_bind_event` / `:871 format_unbind_event` still produce the exact `"AppBound:..."` / `"AppUnbound:..."` event-NAME strings the ADR amendment calls a defect. They have ZERO production callers (only their own unit tests). The live typed path is `EventType::AppBound/AppUnbound` + `AppBoundPayload/AppUnboundPayload`. These dead formatters + `AppBindEvent/AppUnbindEvent` structs are stale anti-pattern code that should be deleted when the App bind/unbind emit site is wired (the deferred-#A work), so a future agent doesn't copy them. Not a regression — they were dead before this change too.
