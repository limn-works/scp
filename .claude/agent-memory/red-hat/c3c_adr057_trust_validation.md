---
name: c3c-adr057-trust-validation
description: Red-team assessment of branch c3c (ADR-057 structured cap validation FFI + §7.3.2 participation facts + verify-on-ingest), HEAD fd3c8b625
metadata:
  type: project
---

# c3c / ADR-057 + §7.3.2 participation-facts assessment (2026-06-30, HEAD fd3c8b625)

Change set: ucan_evaluate (read-only diagnostic, optional capability) vs validate_ucan (gate); participation facts (subject_did/target_did leaves, attestation_count credential-layer); verify-on-ingest for attestations AND challenge_results; presenting_agent_did required fail-closed across 3 bridges.

**Why:** This was a hardening PR responding to a prior white-hat audit (P1/P2-d referenced in code). Heavily tested.

**How to apply:** When reviewing future trust/participation work, the weakest links below are the ones to re-probe.

## What HOLDS UP (verified, do not re-flag as broken)
- **Audience-binding**: presenting_agent_did required + fail-closed + DID-validated, NO aud self-default, on BOTH gate (validate_ucan) and diagnostic (ucan_evaluate), across PyO3/NAPI/UniFFI. UniFFI makes it a non-Optional String + trim check.
- **Challenge replay (context+time)**: verify_challenge_verification binds signed context_id (rejects None + cross-context) + expiry (clock-relative). admission::check_capability_requirements ALSO binds context. Tests confirm.
- **Diagnostic->authz**: NOT reachable. evaluate_ucan intrinsic mode consumed only as a SIGNAL by evaluate_trust; all production enforcement gates use validate_ucan. Spec §7.2.4 + code both forbid gating on diagnostic.
- **Verification-failure-as-success**: does NOT occur. is_verification_rejection is a CLOSED positive allowlist; rejections drop the single entry (fail-closed: lower count); infra faults propagate (fail-closed). lock_error maps to StoreError (outside allowlist) precisely so it propagates.
- **Batch-abort DoS**: NOT reachable. IdentityDidPublicKeyResolver is deterministic (extract key from self-describing DID, no network); unresolvable DID -> AttestationSignatureInvalid which IS a rejection (drop), not infra. One junk-DID entry cannot abort a batch.
- **No raw ingest bypass**: all 3 bridges route caller attestations/challenge results through populate_and_aggregate / verified_attestations (verify-on-ingest). No FFI export hits store_cached_attestation/store_challenge_result raw.
- **Production participation gating is sound**: governance_helpers proposal gate uses meets_threshold on a LOCALLY-COMPUTED record (from real convergent log), not caller-supplied. All gating paths pass &[] attestations (attestation_count=0, fail-closed) and key on participation_count.

## Open findings (weakest links the new facts ride on)
- **RED-C3C-01 (MEDIUM-latent / HIGH-if-wired)**: `verify_statement_signature` (participation.rs) is SELF-CERTIFYING — verifies the signed ParticipationProfile against its OWN embedded signer_public_key, never checks it's the context-derived participation key. So `verify_participation_requirements` (exported to all SDKs) is fully forgeable: attacker mints a profile with inflated counts, self-signs, embeds own pubkey; for min_contexts uses N self-generated keys = N "distinct signers". PRE-EXISTING, rooted in spec privacy design (profile omits context_id by design, so verifier can't re-derive expected key). NOT wired to any production runtime gate — SDK cross-context-admission primitive only. The whole §7.3.2 signed-facts surface this PR builds rides on this.
- **RED-C3C-02 (MEDIUM-latent)**: verify_challenge_verification checks verifier SIGNATURE (self-describing DID = self-certifying) + context + expiry, but NOT verifier trust/authorization. No trusted_verifier concept exists anywhere in scp-protocol/trust. A subject self-signs ChallengeVerification{passed:true,score:100} from a self-generated verifier DID -> passes ingest. Consumed by signal surface + admission::check_capability_requirements (exported, UNWIRED in production). Spec added "Authenticity is not Sybil resistance" for attestation_count but left the analogous challenge-verifier-trust gap undocumented/unguarded.
- **RED-C3C-03 (LOW/INFO)**: attestation_count inflatable by self-issued genuinely-signed attestations from self-generated DIDs (authenticity != distinct principals). Spec NOW documents this explicitly (§7.4.1 "Authenticity is not Sybil resistance"). Not consumed by any production gate. Doc caveat is not mechanically enforced.

## Key files
- crates/scp-protocol/src/trust/participation.rs — verify_statement_signature self-certifying (RED-C3C-01), compute_participation_record
- crates/scp-protocol/src/trust/challenge.rs — verify_challenge_verification (no verifier-trust, RED-C3C-02)
- crates/scp-ffi/common/src/trust_store.rs — verify-on-ingest, is_verification_rejection allowlist
- crates/scp-protocol/src/trust/attestation.rs:631 — IdentityDidPublicKeyResolver (deterministic, self-describing DID only)
