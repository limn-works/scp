# ADR-057 Structured Capability/Trust Validation (C3c) — c4075916d, 2026-06-30

Branch feat/actor-2c-xctx-tool-saga. Spec §7.2.4, ADR-057, lesson
sdk-consume-structured-ffi-results-not-error-prose.md. ZERO blocking findings —
this is a HARDENING change that closes several real vulns. 3 bridges (PyO3/NAPI/
UniFFI) + 4 SDKs (Py/TS/Swift/Kotlin); WASM removed (ADR-055).

## Vulns CLOSED by this change (all verified fixed)
- `check_capability_requirements` (admission.rs) previously did NOT verify the
  verifier Ed25519 signature at all — any caller could pass `{passed:true}` with
  garbage sig and satisfy a ChallengeVerified requirement. Now routes every
  ChallengeVerification through `verify_challenge_verification` (sig + context
  binding + expiry). NOTE: only re-exported in scp-core lib.rs + used in tests —
  NOT wired into a live runtime admission path yet (latent).
- `ucan_evaluate`/`ucan_validate` previously defaulted presenting_agent to the
  token's own `aud` → tautological `aud==aud` audience check → trust inflation
  for tokens addressed to someone else. Now FAIL-CLOSED across all 3 bridges:
  PyO3/NAPI require+trim+reject empty; UniFFI made it a required `String` (type
  level). `ucan_evaluate` capability now Optional (None=intrinsic, skips step-6
  grant-match only — verified it never flips a false→true).
- Read-path fail-open: persisted challenge results + cached attestations were
  served stale forever. `aggregate_trust_input` now re-runs
  `verify_challenge_verification` on every read (drops expired/wrong-ctx);
  `get_verified_attestations` now drops fresh entries that are context-revoked OR
  whose `attestation.expires_at < now` on BOTH fresh and stale paths.
- Verify-on-ingest: caller-supplied attestations carried caller-controlled
  verified_at/ttl — could persist forged "fresh" creds. Now routed through
  `verify_and_cache_with_revocation` (sig vs resolver issuer key + expiry +
  issuer field + context revocation list); trusted verified_at stamped from
  injected clock. Challenge results through `verify_challenge_verification`.
- challenge far-future `completed_at` could evade staleness lower bound — now
  bounded by MAX_COMPLETION_FUTURE_SKEW_SECS (300s, §9.14).

## Error-chokepoint correctness (verified no failure→success)
- New `is_verification_rejection` (trust_store.rs) = CLOSED allowlist of reject
  variants incl. purpose-built `CanonicalizationFailed` (no infra path emits it).
  Infra faults (StoreError/poisoned lock) EXCLUDED → propagate (never silently
  zero trust). `InvalidEventData`/`ChallengeSigningFailed` deliberately excluded.
- All 3 bridges' `participation_record`: ONLY `NoParticipationFacts`→CTX_2076;
  everything else→CTX_2000. verified_attestations infra error→CTX_2000 propagate.
- All 4 SDKs `evaluateTrust`: fold ONLY CTX_2076 into zeroed record, re-raise
  everything else; branch on STRUCTURED `.code`, never prose. Py `_coded_bridge_
  error` passes already-typed ScpError through unchanged + regex-extracts code
  (None on no-match → won't match 2076 → propagates). TS `mapBridgeError` has
  `error instanceof ScpError` pass-through (prevents downgrade). Swift catches
  `ScpError.Context(_, code) where code==noParticipationFactsCode`. Kotlin
  catches `ScpException.Context` checks `e.code != NO_PARTICIPATION_FACTS_CODE`.

## Conservative-drop observation (NOT a vuln)
Read-path filters use `.is_ok()`/`is_some_and` so a resolver INFRA fault during
verification drops that one entry (deflation, fail-closed direction) — doc claims
"only verification failures drop", slight inaccuracy. Safe (under-counts, never
over-counts). canonical_challenge_verification_bytes binds passed/score/expires_at/
context_id via length-prefixed VarBytes (no boundary-shift); completed_at NOT
bound but not consumed by the gate.
