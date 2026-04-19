//! napi-rs bridge for trust engine operations.
//!
//! Exposes trust engine operations to Node.js/Bun:
//!
//! - [`trust_query_score`] — Query participation-based trust data for a DID.
//! - [`trust_verify_attestation`] — Verify an attestation's signature and
//!   validity.
//! - [`trust_create_challenge`] — Create a challenge request.
//! - [`trust_verify_response`] — Verify a challenge response.
//! - [`aggregate_trust_input`] — Aggregate all trust engine layers into a
//!   single `TrustInput` for agent-level evaluation.
//!
//! See ADR-017 in `.docs/adrs/phase-4.md`.

use scp_ffi_common::error_codes as codes;
use std::sync::Arc;

use napi_derive::napi;
use scp_ffi_common::trust_store::InMemoryFfiTrustStore;

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
        code: codes::VALID_7010.to_owned(),
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
        std::time::Duration::from_mins(5),
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
// aggregate_trust_input (§7.3)
// ---------------------------------------------------------------------------

/// Aggregates all trust engine layers into a single `TrustInput` for
/// agent-level evaluation.
///
/// Uses the global `ProtocolRepository` for persistent trust data when
/// initialized (trust data survives across calls); falls back to an
/// ephemeral in-memory store otherwise. See issue #502.
///
/// See ADR-017 acceptance criterion 9, spec §7.3.
#[napi]
#[allow(clippy::too_many_arguments)]
pub fn aggregate_trust_input(
    context_id: String,
    subject_did: String,
    events_json: String,
    merkle_root_json: String,
    consequence_rules_json: String,
    threshold_requirements_json: String,
    attestor_sets_json: String,
    cached_attestations_json: String,
    challenge_results_json: String,
) -> napi::Result<String> {
    if context_id.is_empty() {
        return Err(validation_error("context_id must not be empty"));
    }
    if subject_did.is_empty() {
        return Err(validation_error("subject DID must not be empty"));
    }

    let events: Vec<scp_event_log::Event> = serde_json::from_str(&events_json)
        .map_err(|e| validation_error(&format!("failed to parse events JSON: {e}")))?;

    let merkle_root_vec: Vec<u8> = serde_json::from_str(&merkle_root_json)
        .map_err(|e| validation_error(&format!("failed to parse merkle_root JSON: {e}")))?;
    let merkle_root: [u8; 32] = merkle_root_vec.try_into().map_err(|v: Vec<u8>| {
        validation_error(&format!(
            "merkle_root must be exactly 32 bytes, got {}",
            v.len()
        ))
    })?;

    let consequence_rules: Vec<scp_core::trust::ConsequenceRule> =
        serde_json::from_str(&consequence_rules_json).map_err(|e| {
            validation_error(&format!("failed to parse consequence_rules JSON: {e}"))
        })?;

    let threshold_requirements: std::collections::HashMap<
        scp_core::trust::AttestationType,
        scp_core::trust::ThresholdRequirement,
    > = serde_json::from_str(&threshold_requirements_json).map_err(|e| {
        validation_error(&format!("failed to parse threshold_requirements JSON: {e}"))
    })?;

    let attestor_sets: std::collections::HashMap<
        scp_core::trust::AttestationType,
        Vec<scp_core::trust::AttestorInfo>,
    > = serde_json::from_str(&attestor_sets_json)
        .map_err(|e| validation_error(&format!("failed to parse attestor_sets JSON: {e}")))?;

    let cached_attestations: Vec<scp_core::trust::aggregate::CachedAttestation> =
        serde_json::from_str(&cached_attestations_json).map_err(|e| {
            validation_error(&format!("failed to parse cached_attestations JSON: {e}"))
        })?;

    let challenge_results: Vec<scp_core::trust::ChallengeVerification> =
        serde_json::from_str(&challenge_results_json).map_err(|e| {
            validation_error(&format!("failed to parse challenge_results JSON: {e}"))
        })?;

    // Use persistent storage if the global ProtocolRepository is initialized,
    // otherwise fall back to an ephemeral in-memory store. See issue #502.
    // Dispatches over `ProtocolRepoVariant` so SQLite-backed bridges route
    // trust attestations into the same SQLCipher database as context
    // snapshots and event log entries.
    match crate::runtime::protocol_repository() {
        Some(crate::runtime::ProtocolRepoVariant::InMemory(repo)) => {
            let handle = crate::runtime().handle().clone();
            let bridge =
                scp_core::trust::ProtocolRepositoryTrustBridge::new(Arc::clone(repo), handle);
            scp_ffi_common::trust_store::populate_and_aggregate(
                bridge,
                &context_id,
                &subject_did,
                cached_attestations,
                &challenge_results,
                &events,
                merkle_root,
                &consequence_rules,
                &threshold_requirements,
                &attestor_sets,
            )
            .map_err(|e| validation_error(&e.to_string()))
        }
        Some(crate::runtime::ProtocolRepoVariant::Sqlite(repo)) => {
            let handle = crate::runtime().handle().clone();
            let bridge =
                scp_core::trust::ProtocolRepositoryTrustBridge::new(Arc::clone(repo), handle);
            scp_ffi_common::trust_store::populate_and_aggregate(
                bridge,
                &context_id,
                &subject_did,
                cached_attestations,
                &challenge_results,
                &events,
                merkle_root,
                &consequence_rules,
                &threshold_requirements,
                &attestor_sets,
            )
            .map_err(|e| validation_error(&e.to_string()))
        }
        None => scp_ffi_common::trust_store::populate_and_aggregate(
            InMemoryFfiTrustStore::new(),
            &context_id,
            &subject_did,
            cached_attestations,
            &challenge_results,
            &events,
            merkle_root,
            &consequence_rules,
            &threshold_requirements,
            &attestor_sets,
        )
        .map_err(|e| validation_error(&e.to_string())),
    }
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

    #[test]
    fn aggregate_trust_input_rejects_empty_context() {
        let result = aggregate_trust_input(
            String::new(),
            "did:key:test".to_owned(),
            "[]".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn aggregate_trust_input_rejects_invalid_events_json() {
        let result = aggregate_trust_input(
            "ctx-1".to_owned(),
            "did:key:test".to_owned(),
            "not json".to_owned(),
            "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[]".to_owned(),
        );
        assert!(result.is_err());
    }
}
