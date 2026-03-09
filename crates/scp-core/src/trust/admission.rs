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

use serde::{Deserialize, Serialize};

use super::capability_uri::CapabilityUri;
use super::challenge::{ChallengeType, ChallengeVerification};

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
/// For each requirement:
/// - [`VerificationLevel::SelfAttested`]: the capability URI must appear in
///   `agent_capabilities`, OR a matching [`ChallengeVerification`] record must
///   exist (challenge-verified implies self-attested).
/// - [`VerificationLevel::ChallengeVerified`]: a [`ChallengeVerification`]
///   record with a matching `challenge_type` must exist, the verification must
///   have `passed == true`, and `expires_at` must be greater than
///   `current_time`.
///
/// Returns `Ok(())` if all requirements are met, or the first unmet
/// requirement as an [`AdmissionError`].
///
/// # Parameters
///
/// - `requirements` — The capability requirements to check.
/// - `agent_capabilities` — The agent's self-attested capability URIs.
/// - `challenge_verifications` — The agent's challenge verification records.
/// - `current_time` — Unix timestamp (seconds) for expiry comparison.
///
/// # Errors
///
/// Returns [`AdmissionError::MissingCapability`] if a self-attested capability
/// is not declared, or [`AdmissionError::VerificationRequired`] if a
/// challenge-verified capability lacks a valid (passed, non-expired)
/// verification record.
pub fn check_capability_requirements(
    requirements: &[CapabilityRequirement],
    agent_capabilities: &[CapabilityUri],
    challenge_verifications: &[ChallengeVerification],
    current_time: u64,
) -> Result<(), AdmissionError> {
    for req in requirements {
        let has_verification = challenge_verifications.iter().any(|cv| {
            let ChallengeType::Uri(ref uri) = cv.challenge_type;
            *uri == req.capability && cv.passed && cv.expires_at > current_time
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
    use super::*;
    use crate::trust::challenge::VerificationMethod;

    /// Helper: build a `ChallengeVerification` for a given capability URI.
    fn make_verification(uri: &CapabilityUri) -> ChallengeVerification {
        ChallengeVerification {
            verification_id: "test-challenge-id".to_owned(),
            verifier_did: "did:dht:zChallenger".into(),
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
            context_id: None,
            verifier_signature: Vec::new(),
        }
    }

    fn cap(s: &str) -> CapabilityUri {
        s.parse().unwrap()
    }

    /// A current time that is before the verification's expires_at.
    const NOW: u64 = 1_700_000_100;

    #[test]
    fn empty_requirements_always_passes() {
        let result = check_capability_requirements(&[], &[], &[], NOW);
        assert!(result.is_ok());
    }

    #[test]
    fn self_attested_passes_when_capability_present() {
        let uri = cap("scp:capability:schema-validation/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::SelfAttested,
        }];

        let result = check_capability_requirements(&reqs, &[uri], &[], NOW);
        assert!(result.is_ok());
    }

    #[test]
    fn self_attested_fails_when_missing() {
        let uri = cap("scp:capability:schema-validation/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri,
            verification_level: VerificationLevel::SelfAttested,
        }];

        let result = check_capability_requirements(&reqs, &[], &[], NOW);
        assert!(matches!(
            result,
            Err(AdmissionError::MissingCapability { ref uri })
            if uri == "scp:capability:schema-validation/v1"
        ));
    }

    #[test]
    fn challenge_verified_passes_with_verification_record() {
        let uri = cap("scp:capability:prompt-injection-resistance/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::ChallengeVerified,
        }];

        let verifications = vec![make_verification(&uri)];
        let result = check_capability_requirements(&reqs, &[], &verifications, NOW);
        assert!(result.is_ok());
    }

    #[test]
    fn challenge_verified_fails_without_verification_record() {
        let uri = cap("scp:capability:prompt-injection-resistance/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::ChallengeVerified,
        }];

        // Even if agent claims the capability, ChallengeVerified requires a record.
        let result = check_capability_requirements(&reqs, &[uri], &[], NOW);
        assert!(matches!(
            result,
            Err(AdmissionError::VerificationRequired { ref uri })
            if uri == "scp:capability:prompt-injection-resistance/v1"
        ));
    }

    #[test]
    fn mixed_requirements_first_failure_returned() {
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
        let result = check_capability_requirements(&reqs, &[uri_a], &[], NOW);
        assert!(matches!(
            result,
            Err(AdmissionError::MissingCapability { ref uri })
            if uri == "scp:capability:rate-limit-compliance/v1"
        ));
    }

    #[test]
    fn challenge_verified_satisfies_self_attested() {
        let uri = cap("scp:capability:schema-validation/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::SelfAttested,
        }];

        // Agent does NOT have it in capabilities, but has a verification record.
        let verifications = vec![make_verification(&uri)];
        let result = check_capability_requirements(&reqs, &[], &verifications, NOW);
        assert!(result.is_ok());
    }

    #[test]
    fn mixed_verification_levels_all_pass() {
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
        let result = check_capability_requirements(&reqs, &[uri_a], &verifications, NOW);
        assert!(result.is_ok());
    }

    #[test]
    fn expired_verification_is_rejected() {
        let uri = cap("scp:capability:prompt-injection-resistance/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::ChallengeVerified,
        }];

        let verifications = vec![make_verification(&uri)];
        // expires_at is 1_700_086_400 — use a time after that.
        let result = check_capability_requirements(&reqs, &[], &verifications, 1_700_086_401);
        assert!(matches!(
            result,
            Err(AdmissionError::VerificationRequired { .. })
        ));
    }

    #[test]
    fn failed_verification_is_rejected() {
        let uri = cap("scp:capability:prompt-injection-resistance/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::ChallengeVerified,
        }];

        let mut cv = make_verification(&uri);
        cv.passed = false;
        let result = check_capability_requirements(&reqs, &[], &[cv], NOW);
        assert!(matches!(
            result,
            Err(AdmissionError::VerificationRequired { .. })
        ));
    }

    #[test]
    fn failed_verification_does_not_satisfy_self_attested() {
        let uri = cap("scp:capability:schema-validation/v1");
        let reqs = vec![CapabilityRequirement {
            capability: uri.clone(),
            verification_level: VerificationLevel::SelfAttested,
        }];

        // Verification exists but passed=false — should NOT satisfy self-attested.
        let mut cv = make_verification(&uri);
        cv.passed = false;
        let result = check_capability_requirements(&reqs, &[], &[cv], NOW);
        assert!(matches!(
            result,
            Err(AdmissionError::MissingCapability { .. })
        ));
    }
}
