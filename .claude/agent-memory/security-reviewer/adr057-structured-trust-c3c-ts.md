---
name: adr057-structured-trust-c3c-ts
description: Security review of ADR-057 structured trust + verify-on-ingest + participation_record (branch c3c-ts, HEAD fcd7ee1d7)
metadata:
  type: project
---

# ADR-057 structured trust / verify-on-ingest / participation facts — branch c3c-ts (HEAD fcd7ee1d7) — 2026-06-29 — PASS / ZERO BLOCKING

Reviewed `git diff origin/main...HEAD`, 83 files. WASM removed (3 native bridges PyO3/NAPI/UniFFI).

**Verify-on-ingest (scp-ffi/common/src/trust_store.rs):** SOUND. `populate_and_aggregate` + new `verified_attestations` route every caller attestation through `AttestationCache::verify_and_cache_with_revocation` (Ed25519 sig vs resolver-resolved issuer key + expiry + issuer-field revocation + NEW context external revocation list via `RevocationStateChecker`) BEFORE cache/count; caller `verified_at`/`ttl_secs` ignored (trusted clock stamp). Challenge results verified via new `verify_challenge_verification` (resolver-resolved verifier key over canonical bytes binding passed/score/expires_at/subject) before `store_challenge_result`. Closed allowlist `is_verification_rejection` (6 variants incl ChallengeVerificationSignatureInvalid): rejection→drop+debug-log; INFRA (resolver-resolution failure, store fault, poisoned lock)→PROPAGATE (never silently zeroes trust). No production raw `store_cached_attestation`/`store_challenge_result` caller-data path remains (greps: aggregate.rs:248/282/316 all post-verify; trust_store.rs:255 post-verify; rest are tests). Forged-fresh + genuinely-signed positive tests both present.

**Gate sole enforcer:** `evaluate_ucan` optional `required_capability` ONLY skips step-6 grant-match when None; never flips a false→true (every other stage runs; within_ceiling=step-8 all-att independent). `validate_ucan` keeps MANDATORY capability. Diagnostic/participation facts feed only informational TrustEvaluation, no authz.

**Fail-closed audience:** presenting_agent_did REQUIRED (trim+non-empty+validate_did) in all 3 bridges for BOTH ucan_validate and ucan_evaluate; no silent default to token aud (would make step-5 aud==aud tautology). Tested omitted+empty.

**Error chokepoint:** Python `_coded_bridge_error` (passes ScpError through, recovers `[SCP-CAT-NNNN]` via regex.search=leading code authoritative, code-less→None) + TS `mapBridgeError` (early return on `instanceof ScpError`). Never failure→success. Empty-log = dedicated CTX_2076 (ContextError::NoParticipationFacts from supervisor only on genuinely-empty log); both SDKs branch on `.code===SCP-CTX-2076`, fold to zeroed BehavioralRecord, RE-RAISE all other ContextError (Python `except ContextError as exc: if exc.code != NO_PARTICIPATION_FACTS_CODE: raise`). Prior blanket `except ContextError` masking removed.

**Untrusted FFI input:** `project_payload`/`inject_projection` panic-free, empty/malformed/empty-string→None; cached_attestations JSON parse err→VALID_7059; optional capability empty→absent. supervisor.participation_record fails-closed on Merkle root (zero root only when events empty, never observed since EmptyEventLog returns first).

**Produce/consume symmetry:** governance ChangeRole→append_role_assigned_leaf, add/remove member + broadcast sub/unsub + self join/leave + founder→append_membership_change_leaf (typed MembershipChangePayload/RoleAssignedPayload positional msgpack); compute_participation_record reads same via project_payload. Founder MemberJoined emitted at convergent creation_ts (builder.rs step 8, rollback-on-fail).

**Coverage:** deleted test_ucan_conformance.py (613L) tested the REMOVED `_classify_ucan_error` prose-classification — obsolete, correct deletion. New test_real_ffi.py (383L) adds REAL-FFI audience-mismatch + fail-closed + empty-capability negatives (mocks→real state).

**Minor observations (non-blocking):** (a) participation_record FFI wraps verified_attestations infra Err as ScpError::Validation(VALID_7059) — slight mis-category (infra labeled validation) but still PROPAGATES (fail-closed preserved, distinct from empty-log CTX_2076). (b) caller-supplied attestation/challenge with unresolvable verifier/issuer DID → infra-propagate aborts whole op (self-DoS only; caller poisons own input; evaluate_trust passes []). (c) attestation_count Sybil-inflatable by self-issuance — documented in SDK threat-model docstrings, resistance is threshold/independence path not the count.
