---
name: c3c-trust-signal-assessment
description: Red-team assessment of branch c3c (ucan_evaluate optional-cap diagnostic, verify-on-ingest, read-path re-validation of challenge results/attestations, participation attestation_count)
metadata:
  type: project
---

# C3c trust-signal change set (branch feat/actor-2c-xctx-tool-saga @ c4075916d, 2026-06-30)

Core finding: the ENTIRE change set hardens DIAGNOSTIC/ADVISORY paths. No tainted signal
reaches a wired production authorization gate.

**Why no gate is reachable:**
- `ucan_evaluate` (Option cap, None=intrinsic) is read-only diagnostic. The enforcing gate
  `validate_ucan` keeps MANDATORY required_capability. No production code consumes evaluate_ucan's booleans for allow/deny.
- `attestation_count`: every WIRED `compute_participation_record` caller (lifecycle_logic:261,
  messaging_helpers:2039, governance_helpers:3577+4856, tools/invoke:836) passes `&[]` for
  accessible_attestations → count always 0 at gates. Non-zero only in advisory
  `Supervisor::participation_record` FFI op + `aggregate_trust_input` (SDK trust signal).
- `check_capability_requirements` (the gate that WOULD consume verified challenge results):
  ZERO production callers. Re-exported in scp-core lib.rs, called only by its own tests. Unwired.
- `aggregate_trust_input` / challenge_results: consumed only by FFI `aggregate_trust_input` op
  → serialized TrustInput JSON → SDK advisory. Not a hard gate.

**Controls that HOLD:**
- Audience binding: `ucan_evaluate` requires `presenting_agent_did` (fail-closed, no default to
  token aud). Closes the tautological aud==aud inflation.
- Subject binding on storage: both InMemory (trust_store.rs:77,121) and production
  (store/trust.rs:110 `entry.attestation.subject`, :192 `result.subject_did`) key by the SIGNED
  subject field, not a caller param. Cross-subject injection blocked at ingest.
- attestation_count subject binding: `credential_attestation_history` filters accessible_attestations
  to `subject == subject_did` AND Active revocation_status inside compute_participation_record.
- verify-on-ingest: populate_and_aggregate routes attestations through verify_and_cache_with_revocation
  (sig+expiry+issuer-revocation+context-revocation-list) and challenge results through
  verify_challenge_verification (verifier sig + context binding + expiry) BEFORE store.
- Read-path re-validation: get_verified_attestations drops revoked+expired on BOTH fresh and stale
  paths; aggregate re-runs verify_challenge_verification on every read (context+expiry+sig).
- DoS-resistant classification: unresolvable verifier_did → IdentityDidPublicKeyResolver returns
  AttestationSignatureInvalid (a static parse, no network), which IS in is_verification_rejection
  allowlist → drops ONE entry, never aborts aggregate. Infra faults (StoreError/lock) propagate.
- Closed rejection allowlist keyed on dedicated CanonicalizationFailed variant.

**Residual risks (all LATENT — no wired gate today):**
- RED-C3C-1 (verifier self-certification): verify_challenge_verification authenticates verifier_did
  but verifier_did is self-asserted; NO trusted-verifier-set anywhere. Subject mints own signed
  challenge result (verifier=self-controlled, subject=self, context=target, passed=true) → survives
  verify-on-ingest + aggregation → appears as passed challenge in advisory TrustInput, AND would
  satisfy check_capability_requirements if ever wired. Documented as caller responsibility. This is
  THE primary residual: ingest authenticates, does not authorize the verifier.
- RED-C3C-2 (subject not bound in consumers): aggregate filter (aggregate.rs:510) and
  check_capability_requirements (admission.rs:135) pass context_id but NOT subject_did to
  verify_challenge_verification. Defended TODAY only by store-key derivation. If check_capability_requirements
  is wired to a slice not keyed by subject (e.g. "all results in context"), silent cross-attribution.
  Recommend binding cv.subject_did inside the function.
- RED-C3C-3 (ucan_evaluate None field overload): within_ceiling/signatures_valid mean different things
  under None vs Some (grant-match skipped). Raw diagnostic caller doing per-capability authz under None
  gets false "valid". SDK evaluateTrust uses None only for general validity (safe). Low.
