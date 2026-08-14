# Trust verify-on-ingest + read-path re-validation review (36b941e07) — 2026-06-30

Branch feat/actor-2c-xctx-tool-saga; diff origin/main...HEAD. ADR-053/057, §7.3.2/§7.4.
ZERO concrete defects. Exceptionally well-engineered; security rationale in doc-comments + adversarial tests.

## What landed (all verified sound)
- **Verify-on-ingest (FFI)**: `scp-ffi/common/trust_store.rs` `verify_and_cache_attestations` +
  challenge `verify_challenge_verification` BEFORE store. Caller `verified_at`/`ttl_secs` ignored;
  trusted stamp from injected clock. Closes forged-fresh + persistent-poisoning class.
- **Read-path re-validation**: `aggregate.rs::get_verified_attestations` re-checks context-revocation
  (RevocationMapChecker from get_revocation_state) + attestation own `expires_at` on FRESH entries,
  re-verifies stale. `aggregate_trust_input` filters challenge results through
  `verify_challenge_verification` on every read (persistent SQLCipher store else serves forever).
- **`verify_challenge_verification`** (challenge.rs): sig + context binding (None rejected) + subject
  binding + expiry, all clock-relative. Plus far-future `completed_at` skew bound (5min) in
  `verify_challenge_response`.
- **check_capability_requirements** (admission.rs): now takes resolver+clock+context+subject; each CV
  run through verify_challenge_verification; cross-context/cross-subject/expired/forged all rejected.
- **evaluate_ucan** `required_capability: Option` — diagnostic ONLY (3 bridges, returns
  CapabilityValidation, never enforcement). `validate_ucan` keeps MANDATORY capability. None never
  flips a bool true that another check sets false.
- **Fail-closed audience**: presenting_agent_did REQUIRED (no aud self-default) — pyo3 (Option+reject
  empty), napi (same), uniffi (non-optional String, compile-enforced + reject empty). 4 SDKs all
  non-optional `String`; evaluateTrust passes subjectDid as presenter.
- **Error classification** (`is_verification_rejection`): CLOSED allowlist of credential-rejection
  variants incl. purpose-built `CanonicalizationFailed`. lock_error()→StoreError (infra, outside
  allowlist). Runtime store/trust.rs has tests proving backend faults→StoreError (propagate, not
  swallowed). No infra path produces an allowlisted variant → no fail-open.
- **Error chokepoint**: supervisor.participation_record maps EmptyEventLog→NoParticipationFacts;
  bridges map ONLY that→CTX_2076, else CTX_2000 (fail-closed propagate). Never failure→success.
- **SDK catch (all 4)**: fold only ContextError code==SCP-CTX-2076 → zeroed record; re-raise else.
- **project_payload** (event-log/payload.rs): never panics, malformed→None, empty→None. Subject-bearing
  leaves emitted by runtime (lifecycle_helpers MemberJoined/Left, role). Attribution to affected member.
- **participation merkle root fail-closed**: real root required when events present; [0u8;32] only on
  empty log (which returns EmptyEventLog anyway).

## Key soundness fact
`.is_ok()` drop-on-error filters are sound ONLY because `IdentityDidPublicKeyResolver` is pure
(scp_primitives::extract_public_key_from_did, no network). Documented; if a networked resolver is ever
substituted, those filters MUST distinguish rejection from infra fault. Flagged in-code already.

## Sybil caveat (documented, not a defect)
attestation_count is raw count of authentic-but-self-issuable endorsements — NO Sybil guarantee.
Doc-comments tell consumers to use independence-scored check_threshold_attestation for admission.
