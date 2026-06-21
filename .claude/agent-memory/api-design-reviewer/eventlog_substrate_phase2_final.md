---
name: eventlog-substrate-phase2-final
description: Phase-2 event-log substrate-swap API review (final double-zero) — provider trait, anchored fields, PaymentReceived, EventType doc-split, cross-binding consistency. APPROVED at 4cad781e5 AND 3d96058f5.
metadata:
  type: project
---

# Phase-2 Event-Log Substrate Swap — Final API Review (branch HEAD 4cad781e5)

Verdict: **APPROVED** (merge-gating confirmation). No blocking API findings.

## Re-confirmed at HEAD 3d96058f5 (delta since 4cad781e5) — APPROVED again, no API/interface regression

Delta was doc-correction + consolidation + WASM parity + test-only helpers. No public API change.
- `EventType` empty-leaf vs payload-carrying doc split (lib.rs:171+) now ACCURATE. Empty-leaf governance variants: ProposalCreated, VoteCast, VoteWithdrawn, ProposalResolved, ConflictDetected, ConflictResolved, DeadlockRecovery. Payload-carrying: GovernanceActionExecuted, ProvenanceAttached/Received, ContextTombstoned, ContextMigrationCancelled.
- WASM now appends `b""` for empty-leaf governance variants (manager.rs ~3991/4116/4233/4311) — byte-identical leaf preimage to native (§9.9.3). GovernanceActionExecuted still carries shared GovernanceActionExecutedPayload (manager.rs:2932).
- `convergent_consequence_timestamp` promoted from private governance_logic.rs dup to ONE `pub` helper in scp-protocol consequence.rs:163 — shared by runtime + WASM. Good single-source consolidation (eliminates cross-platform drift).
- `now_ms` cfg-gating (wasm/src/time.rs): non-wasm32 SystemTime fallback compiled OUT of production; hardened-clock preserved; identical `pub fn now_ms() -> f64` both arms. Sound — only enables native-host tests of WASM governance handlers.
- Test helpers (test_event_log_root, test_set_governance, test_insert_context, test_context_event_log_events) all `#[cfg(test)] pub(crate)` — do NOT widen surface.
- `anchored` SDK fields / PaymentReceived / cross-binding rep UNCHANGED in delta. Only `anchored` in delta = governance_logic.rs security doc-comment corrections.
- Cross-impl byte-parity proven via split tests `cross_impl_*_leaf_bytes` (native in scp-runtime wasm_conformance.rs, WASM in wasm/src/consequence.rs) — split needed because scp-runtime test crate can't dev-depend on the wasm cdylib.

## Prior findings confirmed FIXED
- `verify_merkle_chain` → `recompute_event_log_root` rename: complete, zero residual refs (export_import.rs:464).
- Redundant top-level `ContextExport.merkle_root` mirror REMOVED. Root lives only on the signed `snapshot.event_log_merkle_root` (the sole authoritative binding). ContextExport struct (export_import.rs:210) carries no separate unsigned root field.

## Key API surface reviewed (all sound)
- `ContextEventLogProvider` trait (builder.rs:125): typed `EventType` + `EventPayload` + `timestamp_secs: u64`. Excellent docs on the convergent-clock contract (committer-assigned ts for commit-ordered, pre-computed convergent deadline for timer events — never per-member local clock). Empty-string actor_did convention documented.
- Proof seam: `prove_event_inclusion`/`prove_event_consistency`/`rebuild_event_log_for_proof` default methods replay events through the single `scp_event_log` substrate — no second tree to desync. `MerkleEventLogProvider::with_log` is the explicit proof seam.
- `anchored` field appears in THREE consistent places: `PaymentReceipt.anchored` (adapter.rs:290), `ContextEvent::PaymentReceived.anchored` (membership.rs), `ParticipationProfile.tool_invocation_count_anchored` (Rust/Python/TS all matched). All false pre-ADR-051; all documented "consumers MUST NOT treat as Merkle-proven." PaymentReceipt.anchored is an UNSIGNED wire field (outside signing preimage) — doc explicitly warns deserialized value is untrusted.
- `ContextEvent::PaymentReceived` (NEW variant): mirrors existing sibling `PaymentCaptureFailed` exactly (`action: String` shape). Producer downcasts typed `PaidActionType` → label via `paid_action_label()`. Internally consistent with sibling — not divergence.
- Cross-binding: WASM imports `scp_event_log::EventType` DIRECTLY (no parallel taxonomy) → shared by construction. Consequence event-merge is shared `scp_protocol::trust::consequence::merge_consequence_events` called by both native AND WASM (consequence.rs:118).
- `token_revoked_payload` (revoke.rs): NEW shared producer so native+WASM mint byte-identical TokenRevoked leaves. JSON sorted-key encoding documented as convergence-critical.
- FFI common `event_log.rs`: migrated stringly-typed `EventLogEntry` → typed `scp_event_log::Event`. `event_type_label()` is single source of truth for the surfaced event_type string AND the filter clause (lock-step by construction).

## Non-blocking observations (noted, not flagged as changes)
- `event_type_label` uses `format!("{event_type:?}")` — pins the FFI-surfaced event_type string contract to the EventType Debug impl. Variant names are stable protocol taxonomy so low risk; filter/surface drift is eliminated.
- `token_revoked_payload` uses `serde_json::to_vec(..).unwrap_or_default()` — cannot fail for a json! value, but a hypothetical failure yields empty bytes = divergent leaf rather than an error. Defensible (unreachable) but a `?`/expect would be stricter.
- `PaymentReceived.action: String` / `PaymentCaptureFailed.action: String` — untyped where `PaymentReceipt.action_type` is the typed `PaidActionType` enum. Consistent across both sibling variants so changing one would break parity; a typed enum on both would be marginally stronger but is a pre-existing sibling pattern.
