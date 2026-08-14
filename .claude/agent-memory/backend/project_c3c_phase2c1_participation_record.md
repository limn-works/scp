---
name: project-c3c-phase2c1-participation-record
description: Phase 2C-1 typed participation_record op — core ParticipationFacts projection + Supervisor method + 3 native bridge exports; attestations sourced at bridge layer. Phase 2C-2 (SDK wrappers) = issue #1943.
metadata:
  type: project
---

Phase 2C-1 (branch c3c-ts-work, off d1fec867b) exposed the typed participation/behavioral record (§7.3.2) over the 3 NATIVE FFI bridges so SDKs RECEIVE the facts instead of recomputing them (kills Py↔TS divergence by construction). WASM excluded (being removed; native-only by ADR-034).

**Why:** ParticipationRecord carries rich collections (HashMap/Vec) awkward across FFI; each SDK was re-aggregating to counts → divergence.

**How to apply (the shape for future participation/trust FFI work):**
- Core scalar projection: `scp_protocol::trust::ParticipationFacts` (11 fields) + `impl From<&ParticipationRecord>` — the SINGLE canonical flattening (`.len()` / `.values().sum()`, `tool_invocation_count_anchored=false` until ADR-051). `produce_participation_profile` was refactored to consume it, so signed profile + unsigned facts can't drift. Re-exported via scp-protocol::trust and scp-core.
- Runtime: `Supervisor::participation_record(context_id, subject_did, accessible_attestations) -> Result<ParticipationRecord, ContextError>` (supervisor.rs, sync, mirrors `event_log_entries`): gathers FULL UNFILTERED event log (governance_actions_against needs subject-as-TARGET events) + merkle root via `event_log_ref()` + `clock_ref().now_secs()`, calls core `compute_participation_record`. Takes attestations as a PARAM because the Supervisor canNOT reach the trust store (see [[project-supervisor-no-trust-repo]]).
- Attestation source = BRIDGE layer: shared `scp_ffi_common::trust_store::verified_attestations(store, ctx, did, cached) -> Vec<Attestation>` (populates the bridge's ProtocolRepository from caller `cached_attestations_json` then `AttestationCache::get_verified_attestations`) — same wiring as `aggregate_trust_input`/`populate_and_aggregate`. Each bridge: match ProtocolRepoVariant {InMemory|Sqlite} (PyO3 StorageProvider) → verified_attestations → supervisor.participation_record → ParticipationFacts::from → typed record.
- Typed records mirror CapabilityValidation precedent: PyO3 `PyParticipationRecord` (#[pyclass]+#[pyo3(get)], registered via m.add_class in register_trust, has __repr__ → ffi-export-allowlist.json dunder); NAPI `NapiParticipationRecord` (#[napi(object)], u64→i64 widening like NapiTrustScoreResult); UniFFI `ParticipationRecordView` (uniffi::Record). All bridges validate ctx_id+did via shared validate_context_id/validate_did (format, not just is_empty).
- Gates: capability matrix Trust-domain row (4 SDK cells false + exemptions citing #1943); bridge-aliases.json tri-bridge (wasm:[], wasm_required:false) + wasm exemption; pipeline_wiring.rs 4 routing assertions (supervisor→compute_participation_record + 3 bridges→.participation_record(), ratchet 50→54).

**Phase 2C-2 = GitHub issue #1943**: Python/TS/Kotlin/Swift SDK idiomatic wrappers + flip the 4 matrix cells to true. See [[typed-bindings-use-handles]] (trust ops use string context_id, NOT typed handles — match the aggregate_trust_input sibling).
