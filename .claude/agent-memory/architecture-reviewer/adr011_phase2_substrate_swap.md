---
name: adr011-phase2-substrate-swap
description: ADR-011 Phase 2 CODE-side review — runtime provider rewritten onto scp_event_log::EventLog; trait shape, deferred-#A bridge boundary, fmt-blocker, stale equivocation docs
metadata:
  type: project
---

Phase 2 of ADR-011 event-log unification (branch `feat/eventlog-unification-phase2-substrate`, HEAD 964f186) is the CODE-side implementation of the spec amendment I reviewed earlier (see [[adr011-eventtype-unification-amendment]], [[adr011-eventtype-unification]], [[adr011-eventtype-closure-verification]]). It swaps the runtime `MerkleEventLogProvider` substrate from the free-form-string `EventLogEntry`/`"SCP-EXPORT-ENTRY:"` hash-CHAIN onto the canonical RFC 6962 `scp_event_log::EventLog` (typed `EventType`, `tree::append_unsigned_event`, `tree::root`).

**Verdict: CHANGES-NEEDED — architecturally sound, one mechanical CI blocker.**

**What genuinely converged (durable, No-DOA):**
- `EventLogEntry` + `compute_entry_hash` + `entry_hash` DELETED from `providers/event_log.rs`. `ContextLog` now wraps `EventLog`; `append()` builds a typed `Event` (empty signature) and calls `tree::append_unsigned_event` — mirrors WASM `append_log_event`.
- `ContextEventLogProvider` trait (`builder.rs`) retyped: `append_event(event_type: EventType, actor_did, payload: EventPayload)` replacing `(event: &str, ..., Option<&serde_json::Value>)`. Added proof accessors `prove_event_inclusion`/`prove_event_consistency`/`rebuild_event_log_for_proof` (default impls replay events through substrate — single proof seam, no second tree). This trait shape is durable; won't need replacing.
- Store (`store/event_log.rs`) persists `scp_event_log::Event` not `EventLogEntry`.
- Pruning ported to `TruncatedEventLog::from_log_and_checkpoint` + re-chained tail rebuild (`truncate_log_keeping_tail`); structural-retention predicate now typed `scp_event_log::pruning::is_structural_event(&event.event_type)` not string-name match. Canonical pruning model. `debug_assert_eq!` cross-checks truncated boundary vs rebuilt tail.
- Export root now `tree::root` over canonically-appended events (no chain-head) — the ADR-050/§23.16.8 truncation-forgery-closed upgrade.
- RecoveryEpochAdvanced variant LANDED (closes the gap I flagged in [[adr011-eventtype-unification]]). EventType closed at 76, round-trip + closed-count + distinctness tests present.
- All append call-sites converted to EventType (verified governance.rs:1060 `label` is `Vec<EventType>` from apply_commit_retry_outcomes, not a String).
- `EquivocationDetected` + `MessageReceived` correctly NOT appended to durable log — routed to `ContextEvent` receive-buffer/broadcast (matches amendment exclusion list; correct security rationale at queries_helpers.rs:894-916).
- No enforcement files touched; op surface unchanged so no new pipeline_wiring/capability-matrix cells required.

**Deferred-#A bridge boundary is SOUND.** PyO3/NAPI/UniFFI still hold a bridge-local `rt.core.event_log` (UCAN-state tree) separate from the provider tree, but the interim divergence is now two trees with BYTE-IDENTICAL leaves: the bridges sync the UCAN tree from provider `Event`s via `scp_event_log::tree::leaf_hash(entry)` (the canonical `SHA-256(0x00‖rmp_serde(Event))` preimage) + `push_leaf_raw`. Not two divergent models. Follow-on (delete bridge-local logs + route MCP-tool-invoke/UCAN-revoke through provider) is cleanly scoped and not blocking.

**Findings:**
1. BLOCKER (CI): `cargo fmt --all --check` FAILS across ~20 files (governance_helpers, ttl, store/*, export_import, consequence.rs, ffi common+uniffi, supervisor, etc.). Orchestrator ran clippy+nextest but NOT fmt. One `cargo fmt --all` fixes it. Must run before push.
2. Doc drift (non-blocking): `actor/state.rs:934-948` + `queries_helpers.rs:1033-1040` doc comments still describe the OLD design where recording equivocation APPENDS an EventLog entry that advances `local_count` for replay-idempotency. Actual code uses the per-sender `(count,root)` HashSet as sole dedup and does NOT append. Self-contradicting prose; update to match.
3. Simplification (pre-release): consequence-matcher (`trust/consequence.rs::payload_target_did`) is a 3-way fallback — (1) positional rmp [live], (2) JSON-object target_did [live: governance_logic.rs:76,615], (3) legacy null-terminated string [ZERO producers]. Path 3 is dead code; per [[feedback-no-migration-prerelease]] (no persisted data pre-release) delete it → clean 2-format matcher. The 2-format split is acceptable transitional state only if deferred-#A promotes the JSON-object governance_logic producers to typed payloads, collapsing to one format. Flag that as an explicit follow-on requirement, else format-divergence ossifies.

**How to apply:** When the deferred-#A follow-on lands, verify: bridge-local rt.core.event_log DELETED (grep should hit 0), MCP-tool-invoke + UCAN-revoke route through provider.append_event, JSON-object target_did producers (governance_logic.rs) promoted to typed scp_event_log::payload structs, and the path-3 legacy fallback removed.
