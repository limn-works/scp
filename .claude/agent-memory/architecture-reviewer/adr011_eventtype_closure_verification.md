---
name: adr011-eventtype-closure-verification
description: How to independently verify ADR-011's closed EventType taxonomy is a complete cover of runtime append sites
metadata:
  type: project
---

ADR-011 (phase-2.md) defines a CLOSED `EventType` taxonomy (76 variants at commit c6bccc7d5) that must cover every `scp-runtime` Merkle-log append site. Verifying the closure claim:

**Why:** The amendment rejects `Other(String)` and asserts "exactly two exclusions" (`MessageReceived`, `EquivocationDetected`). That claim is only durable if it is checked against the ACTUAL runtime append sites, not the ADR's prose.

**How to apply:**
- Runtime append entrypoints: `ContextEventLogProvider::append_event` / `append_context_event` / `append_context_event_with_payload`. Real Merkle-log appends bump `state.checkpoint_events_since`.
- Enumerate emitted names across `crates/scp-runtime/src/context/**`. Multi-line calls defeat naive grep — use a paren-matching extractor. Watch for non-literal names: `governance_event_label(event)` (governance_helpers.rs:153), `format!("ContextTombstoned:..")` / `AppBound:..` (app_sandbox.rs), JSON-blob tags `{"event":"SpendApproved"}` / TtlExtended (governance_helpers.rs ~2267), `"recovery/epoch_advanced"` (trust_recovery_helpers.rs → maps to `RecoveryEpochAdvanced`, distinct from ADR-007 `KeyEpochAdvance`).
- `comm -23 <runtime-names> <adr-76-set>` should yield EXACTLY `MessageReceived` + `EquivocationDetected`. Verified at c6bccc7d5.
- `ContextEvent` (scp-protocol/src/context/membership.rs:249) is a SEPARATE receive-buffer notification enum, NOT EventType. Local-only signals (DegradedMode/BufferOverflow/SequenceGapDetected/WelcomeGenerated/CheckpointCosignatureRequired) never reach the Merkle log — correctly out of EventType scope.
- Canonical `scp_event_log::Event` (crates/scp-event-log/src/lib.rs) has 7 fields, NO `signing_key_id`. Leaf = `SHA-256(0x00 || serialize(event))` (tree.rs:86, RFC 6962 §2.1) — matches ADR's `SHA-256(0x00 ‖ rmp_serde(Event))`.
- Direction check: `scp_event_log::EventType` had only 36 variants at c6bccc7d5; ADR defines target 76. "in-code-but-not-ADR" set is EMPTY (no phantom provenance). The 40 "in-ADR-not-code" variants are the work the amendment authorizes — correct upstream-first artifact flow.
