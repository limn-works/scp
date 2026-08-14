---
name: c3c-participation-record-op
description: API review of C3C-1 typed participation_record op across PyO3/NAPI/UniFFI bridges; baseline for C3C-2 SDK wrapper review
metadata:
  type: project
---

# C3C-1 typed participation_record FFI op (branch c3c-ts-work, 2026-06-29)

APPROVED. Phase 2C-1 exposes a typed participation/behavioral record so SDKs RECEIVE structured facts instead of recomputing from event-log collections (kills Py↔TS divergence). Native bridges only (PyO3/NAPI/UniFFI); WASM removed (ADR-034, no Supervisor); SDK wrappers = Phase 2C-2.

**Why:** mirrors existing `aggregate_trust_input` precedent but is strictly MORE type-safe — aggregate_trust_input returns `PyResult<String>` (JSON blob), participation_record returns a typed struct. New op is the template, not the JSON-returning sibling.

**How to apply (for C3C-2 SDK wrapper review):**
- Field parity is exact: core `ParticipationFacts` + `PyParticipationRecord`/`NapiParticipationRecord`/`ParticipationRecordView` all have the SAME 11 fields in the SAME order (subject_did, participation_duration_secs, governance_actions_against, governance_actions_by, tool_invocation_count, tool_invocation_count_anchored, context_creation_count, role_progression_count, attestation_count, computed_at, event_log_root). Verify wrappers preserve all 11.
- **Naming seam to resolve at wrapper layer (SUGGESTION, not blocking):** three different developer-facing names for one shape — Python `ParticipationRecord`, TS `NapiParticipationRecord`, Swift/Kotlin `ParticipationRecordView`. Python name collides with the rich core type `ParticipationRecord` (this is the flattened projection of it). Higher-authorability end state = one canonical name (e.g. `ParticipationFacts`) across all SDKs. Inherited-by-default 3-name divergence is consistent with existing precedent (NapiTrustScoreResult etc.) so non-blocking, but make it a conscious wrapper-layer decision.
- NAPI uses `i64` for counts (PyO3/UniFFI use `u64`) — CORRECT per-bridge idiom (napi u64→JS BigInt ergonomically poor; i64→number lossless). Matches sibling `NapiTrustScoreResult`. `#[allow(clippy::cast_possible_wrap)]` scoped+documented. Not a hazard.
- `tool_invocation_count_anchored` is a truth-in-advertising bool (false until ADR-051 makes ToolInvoked a convergent Merkle leaf) — surfaced as a NAMED FIELD on all 4 structs, not buried in docs. Correct misuse-resistance. Ensure SDK wrappers keep it a first-class field, not dropped.
- `cached_attestations_json` string param matches aggregate_trust_input exactly (PyO3 defaults `"[]"`). It's an INPUT-collection serialization boundary (fine); the OUTPUT is now typed. Not a misuse hazard.
- Per-bridge validation differs (PyO3 uses format-aware validate_did/validate_context_id; NAPI+UniFFI use `.is_empty()`) — this is PRE-EXISTING precedent matching each bridge's own sibling, not introduced here.
- Empty event log → `EmptyEventLog` error, never silent zeros. Caller can't mistake no-data for zero-participation. Bridge sources REAL verified attestations via new shared helper `scp_ffi_common::trust_store::verified_attestations` (factored from populate_and_aggregate); never fabricates `&[]`.
- produce_participation_profile refactored to consume `ParticipationFacts::from(&record)` so signed profile + unsigned facts provably can't drift in counting.
