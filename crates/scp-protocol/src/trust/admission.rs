//! Context admission capability requirements with verification levels.
//!
//! Defines [`CapabilityRequirement`] for specifying what capabilities an agent
//! must possess to join a context, and [`VerificationLevel`] to distinguish
//! between self-attested claims and challenge-verified proofs.
//!
//! [`check_capability_requirements`] validates an agent's capabilities against
//! a set of requirements, returning the first unmet requirement as an
//! [`AdmissionError`].
//!
//! See SCP-ACR-007.

use scp_primitives::Clock;
use serde::{Deserialize, Serialize};

use super::attestation::DidPublicKeyResolver;
use super::capability_uri::CapabilityUri;
use super::challenge::{ChallengeType, ChallengeVerification, verify_challenge_verification};

// ---------------------------------------------------------------------------
// VerificationLevel
// ---------------------------------------------------------------------------

/// How a capability must be verified for admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationLevel {
    /// The agent claims the capability (present in their capability list).
    SelfAttested,
    /// The capability has been verified through the challenge-response protocol.
    /// Also satisfies `SelfAttested`.
    ChallengeVerified,
}

// ---------------------------------------------------------------------------
// CapabilityRequirement
// ---------------------------------------------------------------------------

/// A single admission requirement: a capability URI and the minimum
/// verification level needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRequirement {
    /// The capability that must be present.
    pub capability: CapabilityUri,
    /// The minimum verification level required.
    pub verification_level: VerificationLevel,
}

// ---------------------------------------------------------------------------
// AdmissionError
// ---------------------------------------------------------------------------

/// Errors produced when an agent fails to meet admission requirements.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    /// The agent does not possess the required capability at all.
    #[error("missing required capability: {uri}")]
    MissingCapability {
        /// The capability URI that is missing.
        uri: String,
    },

    /// The agent possesses the capability but lacks challenge verification.
    #[error("challenge verification required for capability: {uri}")]
    VerificationRequired {
        /// The capability URI that needs challenge verification.
        uri: String,
    },
}

// ---------------------------------------------------------------------------
// check_capability_requirements
// ---------------------------------------------------------------------------

/// Validates that an agent meets all capability requirements for context
/// admission.
///
/// SECURITY: this verifies the AUTHENTICITY of caller-supplied
/// [`ChallengeVerification`] records — each is run through
/// [`verify_challenge_verification`] (verifier Ed25519 signature over the
/// canonical bytes + context binding + subject binding + expiry, all
/// clock-relative) before it can satisfy any requirement. It does NOT establish
/// that the verifier is
/// *authorized/trusted*: the `verifier_did` is self-certifying, so a subject can
/// present a genuinely-signed result from a verifier it controls. Callers MUST
/// establish verifier legitimacy separately (e.g. a trusted-signer set or
/// context-membership proof). See spec §7.4.
///
/// For each requirement, only verification records that pass
/// [`verify_challenge_verification`] are considered:
/// - [`VerificationLevel::SelfAttested`]: the capability URI must appear in
///   `agent_capabilities`, OR a matching verified record with `passed == true`
///   must exist (challenge-verified implies self-attested).
/// - [`VerificationLevel::ChallengeVerified`]: a verified record with a matching
///   `challenge_type` and `passed == true` must exist.
///
/// Returns `Ok(())` if all requirements are met, or the first unmet
/// requirement as an [`AdmissionError`].
///
/// # Parameters
///
/// - `requirements` — The capability requirements to check.
/// - `agent_capabilities` — The agent's self-attested capability URIs.
/// - `challenge_verifications` — The agent's challenge verification records.
/// - `context_id` — The context the agent is being admitted to. A challenge
///   verification only satisfies a requirement when its signed `context_id`
///   equals this value: a result minted for another context (or a
///   context-agnostic `None` result) MUST NOT satisfy admission here, enforced by
///   [`verify_challenge_verification`].
/// - `subject_did` — The DID of the agent being admitted. A challenge
///   verification only satisfies a requirement when its signed `subject_did`
///   equals this value: a genuine result minted for another subject MUST NOT
///   satisfy this agent's admission (cross-subject attribution), enforced by
///   [`verify_challenge_verification`].
/// - `resolver` — Resolves a `verifier_did` to its Ed25519 public key for
///   signature verification.
/// - `clock` — Injected clock; `verify_challenge_verification` rejects records
///   whose `expires_at <= now`.
///
/// # Errors
///
/// Returns [`AdmissionError::MissingCapability`] if a self-attested capability
/// is not declared, or [`AdmissionError::VerificationRequired`] if a
/// challenge-verified capability lacks a valid (signature-verified, passed,
/// non-expired, in-context, in-subject) verification record.
pub fn check_capability_requirements(
    requirements: &[CapabilityRequirement],
    agent_capabilities: &[CapabilityUri],
    challenge_verifications: &[ChallengeVerification],
    context_id: &str,
    subject_did: &str,
    resolver: &(impl DidPublicKeyResolver + ?Sized),
    clock: &(impl Clock + ?Sized),
) -> Result<(), AdmissionError> {
    // Verify-on-use: a caller-supplied ChallengeVerification only counts if the
    // verifier's signature is authentic AND the record is bound to this context
    // and unexpired. Verify all up front (mirrors
    // `verify_participation_requirements`), keeping only authentic records. A
    // record that fails verification is simply not considered — it falls through
    // to the MissingCapability / VerificationRequired outcome.
    let verified: Vec<&ChallengeVerification> = challenge_verifications
        .iter()
        .filter(|cv| {
            verify_challenge_verification(cv, resolver, context_id, subject_did, clock).is_ok()
        })
        .collect();

    for req in requirements {
        let has_verification = verified.iter().any(|cv| {
            let ChallengeType::Uri(ref uri) = cv.challenge_type;
            *uri == req.capability && cv.passed
        });

        match req.verification_level {
            VerificationLevel::SelfAttested => {
                let has_capability = agent_capabilities.contains(&req.capability);
                if !has_capability && !has_verification {
                    return Err(AdmissionError::MissingCapability {
                        uri: req.capability.to_string(),
                    });
                }
            }
            VerificationLevel::ChallengeVerified => {
                if !has_verification {
                    return Err(AdmissionError::VerificationRequired {
                        uri: req.capability.to_string(),
                    });
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;

    use ed25519_dalek::{Signer, SigningKey};
    use scp_primitives::TestClock;

    use super::*;
    use crate::trust::TrustError;
    use crate::trust::challenge::{VerificationMethod, canonical_challenge_verification_bytes};

    /// A current time that is before the verification's `expires_at`.
    const NOW: u64 = 1_700_000_100;

    /// The context all admission checks below are evaluated under. The
    /// verification records produced by `make_verification` are bound to this
    /// context (their signed `context_id`), so they satisfy requirements here.
    const CTX: &str = "ctx-admission";

    /// The subject all admission checks below are evaluated for. The verification
    /// records produced by `make_verification` are bound to this subject (their
    /// signed `subject_did`), so they satisfy requirements here.
    const SUBJECT: &str = "did:dht:zResponder";

    /// Deterministic verifier signing key used by `make_verification`.
    fn verifier_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    /// A test resolver mapping the verifier DID to its public key bytes.
    struct TestResolver {
        keys: HashMap<String, Vec<u8>>,
    }

    impl DidPublicKeyResolver for TestResolver {
        fn resolve_public_key(&self, did: &str) -> Result<Vec<u8>, TrustError> {
            self.keys.get(did).cloned().ok_or_else(|| {
                TrustError::ChallengeVerificationSignatureInvalid {
                    verification_id: String::new(),
                    reason: format!("DID not found: {did}"),
                }
            })
        }
    }

    /// A resolver that resolves the `make_verification` verifier DID, plus a
    /// clock fixed at `NOW`.
    fn resolver_and_clock() -> (TestResolver, TestClock) {
        let verifier_pub = verifier_key().verifying_key().to_bytes();
        let verifier_did = scp_primitives::did_dht_from_public_key(&verifier_pub).to_string();
        let mut keys = HashMap::new();
        keys.insert(verifier_did, verifier_pub.to_vec());
        (TestResolver { keys }, TestClock::new(NOW))
    }

    /// Helper: build a GENUINELY verifier-signed `ChallengeVerification` for a
    /// given capability URI, bound to [`CTX`].
    fn make_verification(uri: &CapabilityUri) -> ChallengeVerification {
        let verifier_key = verifier_key();
        let verifier_pub = verifier_key.verifying_key().to_bytes();
        let verifier_did = scp_primitives::did_dht_from_public_key(&verifier_pub);

        let mut cv = ChallengeVerification {
            verification_id: "test-challenge-id".to_owned(),
            verifier_did,
            subject_did: "did:dht:zResponder".into(),
            capability_uri: uri.to_string(),
            challenge_type: ChallengeType::Uri(uri.clone()),
            verification_method: VerificationMethod::ChallengeVerified {
                challenge_type: ChallengeType::Uri(uri.clone()),
            },
            passed: true,
            score: None,
            test_count: 1,
            pass_count: 1,
            result: serde_json::Value::Bool(true),
            completed_at: 1_700_000_000,
            verified_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            context_id: Some(CTX.to_owned()),
            verifier_signature: Vec::new(),
        };
        let canonical = canonical_challenge_verification_bytes(&cv).unwrap();
        cv.verifier_signature = verifier_key.sign(&canonical).to_bytes().to_vec();
        cv
    }

    /// Re-signs a mutated verification so its signature stays authentic over the
    /// new field values (used by tests that flip `passed`).
    fn resign(cv: &mut ChallengeVerification) {
        cv.verifier_signature.clear();
        let canonical = canonical_challenge_verification_bytes(cv).unwrap();
        cv.verifier_signature = verifier_key().sign(&canonical).to_bytes().to_vec();
    }

    fn cap(s: &str) -> CapabilityUri {
        s.parse().unwrap()
    }

    #[test]
    fn empty_requirements_always_passes() {
        let (resolver, clock) = resolver_and_clock();
        let result = check_capability_requirements(&[], &[], &[], CTX, SUBJECT, &resolver, &clock);
        assert!(result.is_ok());
    }

    #[test]
    fn self_attested_passes_when_capability_present() {
        let (resolver, clock) = resolver_and_clock();
        let uri = cap("scp:capability:schema-validation/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::SelfAttested,
        }];

        let result =
            check_capability_requirements(&reqs, &[uri], &[], CTX, SUBJECT, &resolver, &clock);
        assert!(result.is_ok());
    }

    #[test]
    fn self_attested_fails_when_missing() {
        let (resolver, clock) = resolver_and_clock();
        let uri = cap("scp:capability:schema-validation/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri,
            verification_level: VerificationLevel::SelfAttested,
        }];

        let result =
            check_capability_requirements(&reqs, &[], &[], CTX, SUBJECT, &resolver, &clock);
        assert!(matches!(
            result,
            Err(AdmissionError::MissingCapability { ref uri })
            if uri == "scp:capability:schema-validation/v1"
        ));
    }

    #[test]
    fn challenge_verified_passes_with_verification_record() {
        let (resolver, clock) = resolver_and_clock();
        let uri = cap("scp:capability:prompt-injection-resistance/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::ChallengeVerified,
        }];

        let verifications = vec![make_verification(&uri)];
        let result = check_capability_requirements(
            &reqs,
            &[],
            &verifications,
            CTX,
            SUBJECT,
            &resolver,
            &clock,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn challenge_verified_fails_without_verification_record() {
        let (resolver, clock) = resolver_and_clock();
        let uri = cap("scp:capability:prompt-injection-resistance/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::ChallengeVerified,
        }];

        // Even if agent claims the capability, ChallengeVerified requires a record.
        let result =
            check_capability_requirements(&reqs, &[uri], &[], CTX, SUBJECT, &resolver, &clock);
        assert!(matches!(
            result,
            Err(AdmissionError::VerificationRequired { ref uri })
            if uri == "scp:capability:prompt-injection-resistance/v1"
        ));
    }

    #[test]
    fn invalid_verifier_signature_does_not_satisfy() {
        // A `passed=true` record whose verifier signature does NOT authenticate
        // (empty signature) must not satisfy a ChallengeVerified requirement.
        let (resolver, clock) = resolver_and_clock();
        let uri = cap("scp:capability:prompt-injection-resistance/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::ChallengeVerified,
        }];

        let mut cv = make_verification(&uri);
        cv.verifier_signature = Vec::new(); // strip the genuine signature
        let result =
            check_capability_requirements(&reqs, &[], &[cv], CTX, SUBJECT, &resolver, &clock);
        assert!(
            matches!(result, Err(AdmissionError::VerificationRequired { .. })),
            "a record with an invalid/empty verifier signature must NOT satisfy the requirement"
        );
    }

    #[test]
    fn invalid_verifier_signature_does_not_satisfy_self_attested() {
        // The forged record must also not satisfy a self-attested requirement via
        // the "challenge-verified implies self-attested" path.
        let (resolver, clock) = resolver_and_clock();
        let uri = cap("scp:capability:schema-validation/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::SelfAttested,
        }];

        let mut cv = make_verification(&uri);
        cv.verifier_signature = vec![0u8; 64]; // non-authenticating signature
        let result =
            check_capability_requirements(&reqs, &[], &[cv], CTX, SUBJECT, &resolver, &clock);
        assert!(matches!(
            result,
            Err(AdmissionError::MissingCapability { .. })
        ));
    }

    #[test]
    fn mixed_requirements_first_failure_returned() {
        let (resolver, clock) = resolver_and_clock();
        let uri_a = cap("scp:capability:schema-validation/v1");
        let uri_b = cap("scp:capability:rate-limit-compliance/v1");
        let reqs = vec![
            CapabilityRequirement {
                capability: uri_a.clone(),
                verification_level: VerificationLevel::SelfAttested,
            },
            CapabilityRequirement {
                capability: uri_b,
                verification_level: VerificationLevel::SelfAttested,
            },
        ];

        // Agent has uri_a but not uri_b.
        let result =
            check_capability_requirements(&reqs, &[uri_a], &[], CTX, SUBJECT, &resolver, &clock);
        assert!(matches!(
            result,
            Err(AdmissionError::MissingCapability { ref uri })
            if uri == "scp:capability:rate-limit-compliance/v1"
        ));
    }

    #[test]
    fn challenge_verified_satisfies_self_attested() {
        let (resolver, clock) = resolver_and_clock();
        let uri = cap("scp:capability:schema-validation/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::SelfAttested,
        }];

        // Agent does NOT have it in capabilities, but has a verification record.
        let verifications = vec![make_verification(&uri)];
        let result = check_capability_requirements(
            &reqs,
            &[],
            &verifications,
            CTX,
            SUBJECT,
            &resolver,
            &clock,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn mixed_verification_levels_all_pass() {
        let (resolver, clock) = resolver_and_clock();
        let uri_a = cap("scp:capability:schema-validation/v1");
        let uri_b = cap("scp:capability:prompt-injection-resistance/v1");
        let reqs = vec![
            CapabilityRequirement {
                capability: uri_a.clone(),
                verification_level: VerificationLevel::SelfAttested,
            },
            CapabilityRequirement {
                capability: uri_b.clone(),
                verification_level: VerificationLevel::ChallengeVerified,
            },
        ];

        let verifications = vec![make_verification(&uri_b)];
        let result = check_capability_requirements(
            &reqs,
            &[uri_a],
            &verifications,
            CTX,
            SUBJECT,
            &resolver,
            &clock,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn expired_verification_is_rejected() {
        // Clock past the verification's expires_at (1_700_086_400).
        let (resolver, _) = resolver_and_clock();
        let clock = TestClock::new(1_700_086_401);
        let uri = cap("scp:capability:prompt-injection-resistance/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::ChallengeVerified,
        }];

        let verifications = vec![make_verification(&uri)];
        let result = check_capability_requirements(
            &reqs,
            &[],
            &verifications,
            CTX,
            SUBJECT,
            &resolver,
            &clock,
        );
        assert!(matches!(
            result,
            Err(AdmissionError::VerificationRequired { .. })
        ));
    }

    #[test]
    fn failed_verification_is_rejected() {
        let (resolver, clock) = resolver_and_clock();
        let uri = cap("scp:capability:prompt-injection-resistance/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::ChallengeVerified,
        }];

        let mut cv = make_verification(&uri);
        cv.passed = false;
        resign(&mut cv);
        let result =
            check_capability_requirements(&reqs, &[], &[cv], CTX, SUBJECT, &resolver, &clock);
        assert!(matches!(
            result,
            Err(AdmissionError::VerificationRequired { .. })
        ));
    }

    #[test]
    fn failed_verification_does_not_satisfy_self_attested() {
        let (resolver, clock) = resolver_and_clock();
        let uri = cap("scp:capability:schema-validation/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::SelfAttested,
        }];

        // Verification exists but passed=false — should NOT satisfy self-attested.
        let mut cv = make_verification(&uri);
        cv.passed = false;
        resign(&mut cv);
        let result =
            check_capability_requirements(&reqs, &[], &[cv], CTX, SUBJECT, &resolver, &clock);
        assert!(matches!(
            result,
            Err(AdmissionError::MissingCapability { .. })
        ));
    }

    #[test]
    fn verification_for_other_context_does_not_satisfy_challenge_verified() {
        let (resolver, clock) = resolver_and_clock();
        let uri = cap("scp:capability:prompt-injection-resistance/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::ChallengeVerified,
        }];

        // A genuine, passed, unexpired verification — but minted for a DIFFERENT
        // context. It must NOT satisfy admission to CTX (replay across contexts).
        let mut cv = make_verification(&uri);
        cv.context_id = Some("ctx-other".to_owned());
        resign(&mut cv);
        let result =
            check_capability_requirements(&reqs, &[], &[cv], CTX, SUBJECT, &resolver, &clock);
        assert!(matches!(
            result,
            Err(AdmissionError::VerificationRequired { .. })
        ));
    }

    #[test]
    fn verification_for_other_subject_does_not_satisfy_challenge_verified() {
        let (resolver, clock) = resolver_and_clock();
        let uri = cap("scp:capability:prompt-injection-resistance/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::ChallengeVerified,
        }];

        // A genuine, passed, unexpired, in-context verification — but its signed
        // `subject_did` is SUBJECT, not the agent being admitted here. It must NOT
        // satisfy admission for a DIFFERENT subject (cross-subject attribution).
        let verifications = vec![make_verification(&uri)];
        let result = check_capability_requirements(
            &reqs,
            &[],
            &verifications,
            CTX,
            "did:dht:zSomeoneElse",
            &resolver,
            &clock,
        );
        assert!(matches!(
            result,
            Err(AdmissionError::VerificationRequired { .. })
        ));
    }

    #[test]
    fn context_agnostic_verification_does_not_satisfy_challenge_verified() {
        let (resolver, clock) = resolver_and_clock();
        let uri = cap("scp:capability:prompt-injection-resistance/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::ChallengeVerified,
        }];

        // A `None` (context-agnostic) verification must not satisfy a
        // context-scoped admission requirement.
        let mut cv = make_verification(&uri);
        cv.context_id = None;
        resign(&mut cv);
        let result =
            check_capability_requirements(&reqs, &[], &[cv], CTX, SUBJECT, &resolver, &clock);
        assert!(matches!(
            result,
            Err(AdmissionError::VerificationRequired { .. })
        ));
    }
}
