---
name: verify-on-ingest-trust
description: Trust verify-on-ingest (attestation + challenge) FFI path soundness + the challenge read-path expiry asymmetry finding (branch feat/actor-2c-xctx-tool-saga, fd3c8b625)
metadata:
  type: project
---

# Trust verify-on-ingest audit (fd3c8b625)

SCOPE: scp-ffi/common/src/trust_store.rs (populate_and_aggregate, verified_attestations),
scp-protocol/src/trust/{challenge.rs verify_challenge_verification, attestation.rs verify_attestation_with_revocation,
aggregate.rs get_verified_attestations}, participation.rs signable_bytes, ucan/validate.rs evaluate_ucan.

GOTCHA: worktree at .claude/worktrees/agent-a1400c1b005b502a3 — the MAIN repo /Users/alec/Developer/limn/scp
is on a DIFFERENT branch (HEAD 1620de983). Read/Bash with main-repo absolute paths read STALE files.
Always git -C <worktree> and read via worktree path.

## SOUND
- Attestation ingest: verify_and_cache_with_revocation verifies Ed25519 vs IdentityDidPublicKeyResolver-resolved
  issuer key, evidence, expiry, issuer-field revocation (revoked_by==issuer), AND external context revocation list.
  Junk/unresolvable issuer DID -> AttestationSignatureInvalid (in is_verification_rejection allowlist) -> drop 1 entry.
  Infra (StoreError, poisoned lock now mapped to StoreError not InvalidEventData) -> propagates (no silent trust-zero).
- Challenge ingest: verify_challenge_verification verifies verifier Ed25519 over canonical_challenge_verification_bytes
  (binds verification_id, verifier_did, subject_did, capability_uri, challenge_type, passed, score[Some U32/None Absent],
  test_count, pass_count, verified_at, expires_at, context_id[Some VarBytes/None Absent]); then context binding (rejects
  None + cross-context replay) + expiry (<= now). Junk verifier DID -> AttestationSignatureInvalid (shared resolver) ->
  rejection -> drop 1. Domain sep SCP-CHALLENGE-VERIFY-V1.
- Read path attestation: get_verified_attestations consults context revocation list on BOTH fresh (else-if check_revocation
  none) and stale (verify_attestation_with_revocation) paths. RevocationMapChecker returns Some(0) when listed.
- participation signable_bytes: SCP-PARTICIPATION-V1, length-prefixed DID, fixed-width u64 BE counts incl attestation_count,
  binds tool_invocation_count_anchored (1 byte). attestation_count_anchored deliberately NOT on signed ParticipationProfile
  at all (permanent const false; lives only on UNSIGNED ParticipationFacts view) -> no malleability. tool flag IS bound
  because it flips to true under ADR-051.
- ucan evaluate_ucan(Option<&CapabilityUri>): None skips ONLY step-6 grant-match, every other step runs (fail-closed);
  nonce step uses check_replay (READ-ONLY, records nothing); gate validate_ucan keeps mandatory cap + check_and_record.
  evaluate_ucan only used as bridge diagnostic, never authz gate.
- Founder MemberJoined: single emit by builder::create_context (supervisor lifecycle_helpers::create_context delegates to
  it at line ~1411), creator-assigned creation_timestamp_secs (convergent), role admin, actor==subject==creator. join/leave
  membership leaves use committer local clock (acknowledged non-convergent until ADR-051 receive-side replication).
- §25 KAT vector_32/33 PASS: root 0c6f6a09ecdda29319880ca609060ec15aa8055ee9fbc85099e5f6e8b1ba4117, event_count 9
  (was 39e50b87/7; added synthetic RoleAssigned+MemberJoined leaves). Synthetic KAT, unaffected by runtime founder emit.

## FINDING (MEDIUM, fail-open asymmetry)
Challenge results get INGEST-time expiry check only. FFI uses PERSISTENT ProtocolRepositoryTrustBridge (not ephemeral
InMemoryFfiTrustStore). aggregate_trust_input step 3 reads get_challenge_results -> load_trust_challenge_results returns
ALL persisted (keyed/idempotent by verification_id, no expiry filter) and puts them in TrustInput WITHOUT re-checking
expires_at. So a challenge verification stored while valid is served as a current trust signal AFTER expires_at,
indefinitely. Asymmetric with the attestation read-path hardening this very PR added (which re-checks expiry+revocation
each read; attestation staleness bounded by 5-min cache TTL, challenge staleness UNBOUNDED). Fix: filter challenge_results
by expires_at > now in aggregate_trust_input step 3 (mirror the attestation read-path).

## LOW
- challenge canonical preimage does NOT bind result, completed_at, verification_method (only the decision-consumed fields
  are signed). No escalation (verification_method has no "higher" trust than ChallengeVerified). Docs claim holds for
  "consumed" fields.
- challenge resolution failure surfaces as AttestationSignatureInvalid (shared IdentityDidPublicKeyResolver) — semantically
  odd but functionally correct (in rejection allowlist).
