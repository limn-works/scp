//! napi-rs bridge for trust engine operations.
//!
//! Exposes trust engine operations to Node.js/Bun:
//!
//! - [`trust_query_score`] — Query participation-based trust data for a DID.
//! - [`trust_verify_attestation`] — Verify an attestation's signature and
//!   validity.
//! - [`trust_create_challenge`] — Create a challenge request.
//! - [`trust_verify_response`] — Verify a challenge response.
//!
//! See ADR-017 in `.docs/adrs/phase-4.md`.

use napi_derive::napi;

use crate::error::ScpNapiError;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Trust score query result.
#[napi(object)]
pub struct NapiTrustScoreResult {
    /// Number of message events attributed to the DID.
    pub message_count: i64,
    /// Number of governance action events attributed to the DID.
    pub governance_count: i64,
    /// Normalized composite score (0.0–1.0).
    pub composite_score: f64,
}

/// Attestation verification result.
#[napi(object)]
pub struct NapiAttestationVerificationResult {
    /// Whether the attestation is valid.
    pub valid: bool,
    /// Chain depth (1 for single attestation).
    pub chain_depth: i32,
    /// Error message if verification failed, empty string if valid.
    pub error_message: String,
}

/// Challenge creation result.
#[napi(object)]
pub struct NapiChallengeResult {
    /// The unique challenge ID (UUID v4).
    pub challenge_id: String,
    /// The serialized challenge request (JSON).
    pub challenge_json: String,
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn validation_error(msg: &str) -> napi::Error {
    napi::Error::from(ScpNapiError::Validation {
        message: msg.to_owned(),
        code: "SCP-VALID-7010".to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Queries participation-based trust data for a DID within a context.
#[napi]
pub fn trust_query_score(did: String, context_id: String) -> napi::Result<NapiTrustScoreResult> {
    if did.is_empty() {
        return Err(validation_error("DID must not be empty"));
    }
    if context_id.is_empty() {
        return Err(validation_error("context_id must not be empty"));
    }

    let (message_count, governance_count) =
        crate::runtime::query_trust_event_counts(&context_id, &did);

    let total = message_count + governance_count;
    #[allow(clippy::cast_precision_loss)]
    let composite_score = (1.0 + total as f64).log10().min(1.0);

    #[allow(clippy::cast_possible_wrap)]
    Ok(NapiTrustScoreResult {
        message_count: message_count as i64,
        governance_count: governance_count as i64,
        composite_score,
    })
}

/// Verifies an attestation's Ed25519 signature, evidence, expiry, and
/// revocation status.
#[napi]
pub fn trust_verify_attestation(
    attestation_json: String,
) -> napi::Result<NapiAttestationVerificationResult> {
    let attestation: scp_core::trust::Attestation = serde_json::from_str(&attestation_json)
        .map_err(|e| validation_error(&format!("failed to parse attestation JSON: {e}")))?;

    let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
    let clock = scp_identity::cache::SystemClock;

    match scp_core::trust::verify_attestation(&attestation, &resolver, &clock) {
        Ok(()) => Ok(NapiAttestationVerificationResult {
            valid: true,
            chain_depth: 1,
            error_message: String::new(),
        }),
        Err(e) => Ok(NapiAttestationVerificationResult {
            valid: false,
            chain_depth: 0,
            error_message: format!("{e}"),
        }),
    }
}

/// Creates a challenge request for capability verification.
#[napi]
pub fn trust_create_challenge(target_did: String) -> napi::Result<NapiChallengeResult> {
    if target_did.is_empty() {
        return Err(validation_error("target DID must not be empty"));
    }

    struct EphemeralSigner(ed25519_dalek::SigningKey);
    impl scp_core::trust::ChallengeSigner for EphemeralSigner {
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, scp_core::trust::TrustError> {
            use ed25519_dalek::Signer;
            let sig = self.0.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
    }

    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let signer = EphemeralSigner(signing_key);

    let request = scp_core::trust::issue_challenge(
        "did:key:ephemeral-challenger".into(),
        target_did.into(),
        scp_core::trust::ChallengeType::schema_validation(),
        "scp:capability:schema-validation/v1".to_string(),
        serde_json::json!({}),
        std::time::Duration::from_secs(300),
        &signer,
    )
    .map_err(|e| validation_error(&format!("challenge creation failed: {e}")))?;

    let challenge_json = serde_json::to_string(&request)
        .map_err(|e| validation_error(&format!("failed to serialize challenge: {e}")))?;

    Ok(NapiChallengeResult {
        challenge_id: request.challenge_id,
        challenge_json,
    })
}

/// Verifies a challenge response against its original challenge request.
#[napi]
pub fn trust_verify_response(challenge_json: String, response_json: String) -> napi::Result<bool> {
    let request: scp_core::trust::ChallengeRequest = serde_json::from_str(&challenge_json)
        .map_err(|e| validation_error(&format!("failed to parse challenge JSON: {e}")))?;

    let response: scp_core::trust::ChallengeResponse = serde_json::from_str(&response_json)
        .map_err(|e| validation_error(&format!("failed to parse response JSON: {e}")))?;

    let resolver = scp_core::trust::IdentityDidPublicKeyResolver;
    let clock = scp_identity::cache::SystemClock;

    struct EphemeralSigner(ed25519_dalek::SigningKey);
    impl scp_core::trust::ChallengeSigner for EphemeralSigner {
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, scp_core::trust::TrustError> {
            use ed25519_dalek::Signer;
            let sig = self.0.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
    }

    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let signer = EphemeralSigner(signing_key);

    Ok(scp_core::trust::verify_challenge_response(
        &request, &response, &resolver, &clock, &signer, None,
    )
    .is_ok())
}

// ---------------------------------------------------------------------------
// verify_participation_requirements (SCP-BA-004)
// ---------------------------------------------------------------------------

/// Verifies participation profiles against admission requirements.
///
/// Both inputs are JSON strings:
/// - `profile_json`: JSON array of `ParticipationProfile` objects.
/// - `requirements_json`: JSON array of `RequireParticipation` objects.
///
/// Uses the current system time for freshness checks. Returns `true` if all
/// requirements are satisfied, throws an error with a diagnostic message
/// if any requirement fails or if the JSON is malformed.
///
/// See §7.3.2.1.
#[napi]
pub fn verify_participation_requirements(
    profile_json: String,
    requirements_json: String,
) -> napi::Result<bool> {
    let profiles: Vec<scp_core::trust::ParticipationProfile> = serde_json::from_str(&profile_json)
        .map_err(|e| {
            validation_error(&format!("failed to parse participation profiles JSON: {e}"))
        })?;

    let requirements: Vec<scp_core::trust::RequireParticipation> =
        serde_json::from_str(&requirements_json).map_err(|e| {
            validation_error(&format!(
                "failed to parse participation requirements JSON: {e}"
            ))
        })?;

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    scp_core::trust::verify_participation_requirements(current_time, &requirements, &profiles)
        .map_err(|e| {
            validation_error(&format!("participation admission verification failed: {e}"))
        })?;

    Ok(true)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn trust_query_score_validates_empty_did() {
        let result = trust_query_score(String::new(), "ctx".to_owned());
        assert!(result.is_err());
    }

    #[test]
    fn trust_query_score_validates_empty_context() {
        let result = trust_query_score("did:key:test".to_owned(), String::new());
        assert!(result.is_err());
    }

    #[test]
    fn trust_query_score_returns_zeros_for_unknown_context() {
        let result = trust_query_score("did:key:test".to_owned(), "nonexistent-ctx".to_owned());
        assert!(result.is_ok());
        let score = result.unwrap();
        assert_eq!(score.message_count, 0);
        assert_eq!(score.governance_count, 0);
    }

    #[test]
    fn trust_create_challenge_validates_empty_did() {
        let result = trust_create_challenge(String::new());
        assert!(result.is_err());
    }

    #[test]
    fn trust_create_challenge_succeeds() {
        let result = trust_create_challenge("did:key:target".to_owned());
        assert!(result.is_ok());
        let challenge = result.unwrap();
        assert!(!challenge.challenge_id.is_empty());
        assert!(!challenge.challenge_json.is_empty());
    }

    #[test]
    fn trust_verify_attestation_rejects_invalid_json() {
        let result = trust_verify_attestation("not json".to_owned());
        assert!(result.is_err());
    }

    #[test]
    fn trust_verify_response_rejects_invalid_json() {
        let result = trust_verify_response("bad".to_owned(), "bad".to_owned());
        assert!(result.is_err());
    }

    #[test]
    fn verify_participation_requirements_rejects_invalid_profile_json() {
        let result = verify_participation_requirements("not json".to_owned(), "[]".to_owned());
        assert!(result.is_err());
    }

    #[test]
    fn verify_participation_requirements_rejects_invalid_requirements_json() {
        let result = verify_participation_requirements("[]".to_owned(), "not json".to_owned());
        assert!(result.is_err());
    }

    #[test]
    fn verify_participation_requirements_empty_inputs_succeeds() {
        let result = verify_participation_requirements("[]".to_owned(), "[]".to_owned());
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
