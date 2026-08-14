---
name: c3c-ts-adr057-participation
description: Branch c3c-ts (ADR-057 structured cap/trust validation + §7.3.2 participation facts) adversarial review findings
metadata:
  type: project
---

# c3c-ts review (ADR-057 + participation facts §7.3.2)

Reviewed @fcd7ee1d7. WASM removed; assessed PyO3/NAPI/UniFFI + Py/TS SDKs.

## Findings
- MEDIUM cross-context challenge-result replay: `verify_challenge_verification(verification, resolver)` (challenge.rs:786) verifies ONLY the verifier Ed25519 sig — it takes NO target context, so it structurally cannot bind context. Ingest call sites in trust_store.rs `populate_and_aggregate` call it then `store_challenge_result(context_id, cr)` filing under the AGGREGATION context regardless of `cr.context_id` (which is `Option`, None allowed). A verifier-signed result for context A (or None) replays into context B. Downstream `admission.rs:109 check_capability_requirements` also ignores context_id (only passed+expiry+uri). Fix: ingest must require `cr.context_id == Some(target)` (reject None/mismatch). NOTE admission fn currently only re-exported, not wired as live gate.
- LOW/MED test masking: `forged_challenge_result_excluded_by_populate_and_aggregate` PASSES with sig check fully removed (PROVEN by mutation) — rejection comes from `did:key:verifier` being UNRESOLVABLE (hex decode fail), not signature verification. No positive "genuinely-signed challenge survives ingest" test (attestation path HAS both, and its negative test uses resolvable did:key:00..ff so it DOES exercise the sig branch). Asymmetry.
- LOW: `attestation_count` inflatable via self-issued valid attestations (resolver extracts pubkey FROM the DID string, so attacker self-signs with own DID; distinct ids + distinct issuer DIDs → count N about any victim subject). Durably persisted via ProtocolRepositoryTrustBridge → cross-call poisoning. By-design unanchored (anchored=false) and NOT used for governance eligibility (those pass &[]). Counts validly-signed data; weighting is attestor-trust layer's job.
- Minor: challenge ingest checks neither expiry nor revocation (attestation ingest checks both + context revocation list). Expiry IS checked at admission consumer; challenge revocation is not a concept.

## Resists attack (solid)
- UCAN diagnostic+gate fail-closed on presenting_agent_did across ALL 3 bridges (trim/empty→err, validate_did, agent_did wired into ValidationContext, never aud). Optional capability only skips step-6 grant-match, never flips a bool true. Diagnostic NOT used as auth gate (separate ucan_validate keeps mandatory cap).
- Attestation verify-on-ingest sound (verify_attestation_with_revocation: sig vs resolver key, evidence, expiry, field-revocation issuer-check, external context revocation list). is_verification_rejection closed allowlist; infra errors propagate.
- Founder MemberJoined leaf (builder.rs create_context): single-emit (creator does NOT go through join_context), convergent creation_timestamp_secs, subject==creator, rollback on append fail. No double-emit.
- Participation: payload subject_did/target_did written server-side under authorization; governance_actions_against adverse-only (H18); error chokepoint re-raises all non-CTX_2076; EmptyEventLog→CTX_2076 distinct.
