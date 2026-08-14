# Trust Layer-4 / ADR-057 structured-results audit (branch feat/actor-2c-xctx-tool-saga @50c7bad60) -- 2026-06-30

CLEAN, zero security defects. Large trust/attestation/participation/challenge change set
(scp-protocol trust/*, scp-ffi common+3 bridges, 4 SDKs). Exceptionally well-audited.

Paths verified sound:
- get_verified_attestations (aggregate.rs): read-path re-validation -- context revocation
  checked on EVERY read (fresh + stale paths) + attestation.expires_at on fresh path +
  full re-verify on stale path. fail-closed (drop-only).
- aggregate_trust_input: challenge results RE-VALIDATED on read via
  verify_challenge_verification (verifier-sig + context-bind + subject-bind + expiry, clock-rel).
  Infra-fault caveat documented (resolver is pure/total IdentityDidPublicKeyResolver).
- check_capability_requirements (admission.rs): filters challenge_verifications through
  verify_challenge_verification with context_id+subject_did BEFORE honoring passed==true.
- verify-on-ingest (trust_store.rs populate_and_aggregate/verified_attestations): every
  caller attestation -> verify_and_cache_with_revocation (sig vs resolver issuer key, expiry,
  issuer-field + context revocation list), trusted verified_at stamped (caller's ignored);
  every challenge -> verify_challenge_verification. Rejection drops 1 entry, INFRA fault propagates.
- is_verification_rejection: CLOSED allowlist. CanonicalizationFailed is dedicated variant
  (canonical_attestation_bytes + canonical_challenge_verification_bytes emit it) classified
  as rejection; InvalidEventData/ChallengeSigningFailed EXCLUDED; StoreError(lock poison)=infra.
- fail-closed audience: all 3 bridges reject empty/absent presenting_agent_did (PyO3+NAPI
  Option.filter(!is_empty); UniFFI String trim().is_empty()->VALID_7010). All 4 SDKs pass
  subjectDid AS presentingAgentDid with correct positional order (TS native call maps
  capability,presentingAgentDid correctly despite SDK sig order).
- error chokepoint: NoParticipationFacts->CTX_2076 ONLY; everything else->CTX_2000 propagating;
  verified_attestations infra fault->CTX_2000 NEVER folded into empty-log path. Identical
  across PyO3/NAPI/UniFFI.
- SDK catch (Py/TS/Swift/Kotlin): branch STRICTLY on structured CTX_2076 code, re-raise/throw
  all else. Empty-token-set -> all-false CapabilityValidation (no false trust) in all 4.
- evaluate_ucan now takes Option<&CapabilityUri>: None skips ONLY step-6 grant-match; audience
  step-5, ceiling step-8, sig, attenuation, nonce, revocation all still run. Fail-closed
  (None never flips a bool true). Enforcing validate_ucan keeps mandatory capability.
- ProtocolRepositoryTrustBridge (runtime store/trust.rs): sanitize_key_component rejects
  traversal/null-byte; trust/ namespace isolated; infra faults -> StoreError (propagate).

Known (NOT a code defect): TS evaluateTrust audience-binding has no mutation-killing test
(see project memory finding_c3c). Verified CODE is correct; test-quality gap only.
