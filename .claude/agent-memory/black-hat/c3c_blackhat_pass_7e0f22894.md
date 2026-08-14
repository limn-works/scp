---
name: c3c-blackhat-pass-7e0f22894
description: c3c-ts trust-hardening @7e0f22894 black-hat re-attack — CLEAN, no exploitable findings; prior attestation_count HIGH now CLOSED
metadata:
  type: project
---

# c3c-ts trust-hardening @7e0f22894 — black-hat CLEAN

Re-attacked the trust substrate after Fix-10 + canonicalization-propagation landed. NO exploitable vuln found. All 9 hardening claims verified:

1. Participation subject-binding: all 4 SDKs (Py trust.py / TS scp.ts / Swift+Kotlin via UniFFI free fn) → 3 bridges → `scp_core::trust::verify_participation_requirements`. Insecure twins gone (Participation.kt deleted; Swift moved to UniFFI). No client-side threshold-only verifier remains (grep: Swift/Kotlin Trust.* only have data-model doc-comments). Core Step-0 filter `s.subject_did == expected_subject`. MUTATION-PROVEN: removing filter → `verify_rejects_cross_subject_profile_replay` FAILS.
2. Core rejects empty expected_subject (participation.rs:1011 `EmptyExpectedSubject`) BEFORE the empty-requirements short-circuit.
3. All 3 bridges call `validate_did(expected_subject)` (full did:method:id format, not just non-empty) before core.
4. attestation_count (my prior HIGH `c3c_attestation_count_freshness_bypass`) CLOSED: `verify_and_cache_attestations` (trust_store.rs:213) routes caller entries through `verify_and_cache_with_revocation` (Ed25519 vs resolver-resolved issuer + expiry + revocation), caller `verified_at` ignored; rejection drops one entry, infra propagates. Read-path `get_verified_attestations` re-checks context revocation on fresh+stale.
5. Challenge verify-on-ingest (trust_store.rs:296) AND read-path re-validate (aggregate.rs:531) via `verify_challenge_verification`: verifier-sig + subject_did binding + context_id binding (rejects None) + expiry. All over signed fields.
6. `is_verification_rejection` = closed positive `matches!` allowlist incl CanonicalizationFailed. Both misclassification directions fail-safe for positive-signal counts (drop reduces / propagate denies — neither inflates).
7. Challenge req/resp canonicalization returns Result, propagates (challenge.rs:421/458) — no prod unwrap_or_default. Remaining unwrap() in trust crate all #[cfg(test)].
8. presenting_agent_did required/fail-closed in all 3 bridges + 4 SDK wrappers (UniFFI typed String non-null); audience = presenting_agent_did (non-tautological).
9. evaluate_ucan now `Option<&CapabilityUri>`; None skips ONLY step-6 grant-match (audience step-5 + all others run unconditionally, `?`-short-circuit). Called ONLY from 3 FFI ucan_evaluate diagnostics. Gate `validate_ucan` (validate.rs:545) keeps MANDATORY cap — no runtime authz uses the diagnostic.

Read-path `.is_ok()` (aggregate.rs) sound: `IdentityDidPublicKeyResolver` → `extract_public_key_from_did` is pure total string-parse (zbase32/hex, NO network). Documented latent: if networked resolver substituted, must distinguish reject vs infra. NOT prod-reachable.

DOCUMENTED CAVEAT (not a regression, pre-existing §7.4, file-to-issue): signer legitimacy is self-certifying — a subject who IS expected_subject can mint N self-controlled signers to inflate min_contexts / attestation_count. PR documents it; Sybil resistance is §7.3.5 threshold/independence path. Not closed by this PR by design.

No raw trust-store write op exposed via FFI (writes only inside verify-on-ingest). 501 trust unit tests pass.
