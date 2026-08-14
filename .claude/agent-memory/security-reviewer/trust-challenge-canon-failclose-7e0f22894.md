# Trust challenge canonicalization fail-close + full trust hardening re-audit (7e0f22894) -- 2026-06-30 -- ZERO FINDINGS

Branch feat/actor-2c-xctx-tool-saga @ HEAD 7e0f22894. Same cumulative trust change set as prior
ZERO-finding entries (36b941e07 / 50c7bad60 / fd3c8b625 / fcd7ee1d7); HEAD adds ONE fail-close fix.

HEAD fix (challenge.rs canonical_challenge_request_bytes:421 / _response_bytes:458): replaced
`jcs::to_vec(&parameters|&result).unwrap_or_default()` (fail-OPEN: empty bytes silently dropped
params/result from the SIGNED digest) with `.map_err(|e| TrustError::ChallengeSigningFailed{..})?`.
All non-test callers propagate via `?` (653/724/751/812/876); `.unwrap()` sites all in test mod
(>L1000). Sign & verify both fail-closed & symmetric. Sibling verification-bytes already fail-closed.

Re-verified enumerated properties:
- verify_participation_requirements (participation.rs:998): rejects empty expected_subject
  (1010 EmptyExpectedSubject) BEFORE Step-0 filter; subject-binds via filter (1024
  s.subject_did==expected_subject); verify_statement_signature on ALL filtered statements (1030);
  signable_bytes covers subject_did LENGTH-PREFIXED + signer_public_key + all fact fields (auth'd
  field, no ambiguity). All 3 bridges validate_did(expected_subject): PyO3 trust.rs:277, NAPI
  trust.rs:285, UniFFI bridge.rs (full DID-format, not just non-empty).
- Insecure Swift/Kotlin participation-verifier TWINS DELETED: Kotlin Participation.kt -127 lines,
  no Swift Participation.swift. Remaining verifyParticipationRequirements resolves ONLY to
  UniFFI-generated free fn (secure core path); Scp.kt:1913 + Swift Scp.swift comment confirm.
- Fail-closed audience: validate.rs verify_audience(token, ctx.presenting_agent_did) strict
  `token.payload.aud != presenting_agent_did` (925); presenting_agent_did is required &str field
  (494), no aud self-default anywhere in prod (grep clean; only doc-comments explaining WHY not).
- CanonicalizationFailed = purpose-built closed-allowlist variant (trust_store.rs:192);
  is_verification_rejection = closed matches! defaulting false->infra-propagate;
  ChallengeSigningFailed + InvalidEventData EXPLICITLY excluded (177-179) so signing/infra faults
  never silently drop trust. Chokepoint never maps failure->success.
- SDK catch folds ONLY empty-log SCP-CTX-2076: py trust.py:766 `if exc.code != NO_PARTICIPATION_
  FACTS_CODE: raise`; ts scp.ts:2521 `error instanceof ContextError && error.code === ...`; all
  else propagates. TS resolves contextId from handle (matches Swift/Kotlin), no label/lookup drift.
