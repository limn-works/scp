---
name: participation-record-2c1-review
description: Phase 2C-1 typed participation record (core+3 bridges) — CLEAN review, branch c3c-ts-work
metadata:
  type: project
---

# Phase 2C-1 ParticipationRecord typed FFI — CLEAN (branch c3c-ts-work, 2026-06)

Review of `Supervisor::participation_record` + `ParticipationFacts` + PyO3/NAPI/UniFFI typed records.
NO real bugs. All 3 supervisor integration tests + 4 PyO3 unit tests pass; compiles clean.

Verified correct:
- `From<&ParticipationRecord> for ParticipationFacts` flattening is BYTE-IDENTICAL to old
  produce_participation_profile (.len() over gov/role/attestation Vecs; .values().sum() over
  tool_invocations HashMap; anchored=false). Refactor introduced no behavior change.
- NAPI u64->i64 `as i64`: lossless (counts bounded by log size, timestamps ~10^10, both << i64::MAX
  and << JS 2^53 safe-int). Matches NapiTrustScoreResult precedent. Not a bug.
- Supervisor merkle_root `.unwrap_or([0u8;32])` swallows ONLY the no-log error; that path always
  also yields empty events -> core EmptyEventLog error. Never produces a wrong record. (TOCTOU
  destroy-mid-read window between entries() and merkle_root() is theoretical only.)
- trust_store::verified_attestations mirrors populate_and_aggregate exactly. Persistent store has
  REPLACE-BY-ID semantics (store/trust.rs:96) -> re-storing caller attestations does NOT double-count.
- compute_participation_record filters attestations by subject==subject_did AND Active. Gov-against
  requires is_adverse_action_type (RemoveMember IS adverse). Duration/role/membership key on PROJECTED
  subject_did not actor -> admin-driven events correctly attributed to affected member.
- Test build_supervisor passes clock:None but with_providers defaults Arc::new(SystemClock) -> clock_ref
  is Some. Test genuinely proves: gov-against attributed to target(Bob) not actor(ADMIN) via FULL
  unfiltered log; attestation subject+Active filtering; 300s duration.

CORRECTION (re-review 2026-06-29): the earlier "NAPI/UniFFI only check is_empty()" note is now STALE/WRONG.
Current code: NAPI participation_record_on calls scp_ffi_common::validate::validate_context_id + validate_did
(full format), UniFFI participation_record calls validate_context_id/validate_did. Both have
participation_record_rejects_malformed_did tests. Cross-bridge validation is now SYMMETRIC. No finding.

Additional verified (re-review): context-id keying consistent end-to-end — participation read uses
context_id_to_bytes -> scp_protocol::context::context_id_bytes (plain SHA-256); event-log WRITE
(builder.rs:834 id_bytes) uses the SAME fn. (Existing event_log_entries doc saying "routing-id-hashed"
is a doc error; actual key is plain SHA-256, not the scp:context-routing: domain-separated routing id.)

Only remaining minor (SUGGESTION): cross-bridge error-code asymmetry — UniFFI uses VALID_7059 (new
participation code) for malformed cached_attestations_json + verified-attestations failure; PyO3 uses
VALID_7005/context errors; NAPI uses VALID_7010/CTX_2000. Not a bug (each bridge's existing convention).
And PyO3 defaults cached_attestations_json="[]" while NAPI/UniFFI require it (Phase 2C-2 #1943 harmonizes).
