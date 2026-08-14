---
name: c3c-participation-subject-binding
description: Audit of verify_participation_requirements subject-binding fix (branch c3c-blackhat, HEAD caff1e32d) — fix is sound; Swift/Kotlin local-overload footgun
metadata:
  type: project
---

# Participation subject-binding fix audit (c3c)

Branch c3c, HEAD caff1e32d. Fix: `verify_participation_requirements` takes
required `expected_subject`, drops profiles whose signed `subject_did !=
expected_subject` before threshold/freshness/min_contexts accounting.

**VERIFIED SOUND.** Cross-subject participation-profile replay is closed:
- `subject_did` IS the first length-prefixed field in `signable_bytes()`
  (participation.rs ~770). Keep victim's subject_did → filtered out; edit it to
  attacker's DID → `verify_strict` signature fails. Both directions fail-closed.
- Threaded through ALL 3 bridges: PyO3 (validate_did), NAPI (empty reject),
  UniFFI (empty reject) → core. Class wrappers Python/TS/Kotlin(SCP.kt:1913)/
  Swift(generated) all pass expected_subject.
- distinct_signers (min_contexts) built only over subject-filtered set.
- No runtime/node admission consumer — admission is consumer-composed.

## FINDING (MEDIUM, latent, pre-existing): Swift+Kotlin no-verification overload
- `bindings/swift/Sources/SCP/Trust.swift:990` and
  `bindings/kotlin/.../Participation.kt:90`: PUBLIC pure-local
  `verifyParticipationRequirements(requirement, profile)` doing only
  `observed >= minimum` on a fabricatable dict (Swift `[ParticipationFact:UInt64]`,
  Kotlin facts list). NO subject binding, NO signature, NO freshness, NO
  min_contexts. Same NAME as the security-critical bridge function.
- Kotlin doc FALSELY claims "matching the Rust trust module's
  verify_participation_requirements logic." Python & TS expose NO such overload.
- Pre-existing on origin/main (not introduced here) but violates the change set's
  "4 SDKs at parity" claim. check-sdk-coverage matches by NAME so the insecure
  overload satisfies the coverage gate.

## Rest of substrate — all SOUND
- evaluate_ucan now Option<capability>; None skips step-6 grant-match (diagnostic
  only). validate_ucan keeps MANDATORY capability + all 11 steps. No authz path
  consumes the diagnostic. None never flips a false→true.
- presenting_agent_did REQUIRED/fail-closed across all 3 bridges (closes aud
  tautology).
- verify-on-ingest (trust_store.rs): attestations + challenge results verified
  before cache; is_verification_rejection is a CLOSED allowlist incl
  CanonicalizationFailed; infra faults propagate (no silent trust-zeroing).
- Read-path get_verified_attestations (aggregate.rs:273): both fresh-TTL and
  expired-TTL paths honor post-cache context revocation + underlying expires_at.
- verify_challenge_verification: verifier-sig over canonical preimage binding
  subject_did + context_id (None rejected) + expires_at, all checked at verify
  site. Self-cert/Sybil caveat documented (consumer must apply attestor sets).
