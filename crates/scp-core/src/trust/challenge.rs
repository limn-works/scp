//! Challenge-response protocol for trust verification.
//!
//! Enables verification of testable capabilities through a structured
//! challenge-response flow. Standard challenge suites include prompt injection
//! resistance, schema validation, and rate limit compliance.
//!
//! # Flow
//!
//! 1. A challenger issues a [`ChallengeRequest`] via [`issue_challenge`],
//!    signing the request with their Ed25519 key.
//! 2. The subject produces a [`ChallengeResponse`] containing the result.
//! 3. The challenger verifies the response via [`verify_challenge_response`],
//!    which checks the responder's signature, validates the response matches
//!    the challenge parameters, and produces a [`ChallengeVerification`].
//!
//! # Verification Method
//!
//! [`ChallengeVerification`] distinguishes between self-attested capabilities
//! (claims made without independent verification) and challenge-verified
//! capabilities (validated through this protocol). This distinction is
//! captured in [`VerificationMethod`].
//!
//! See ADR-017 acceptance criteria 4-5 in `.docs/adrs/phase-4.md`.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::crypto::ed25519::verify_ed25519_signature;
use crate::event_log::Ed25519Signature;
use crate::identity::DID;
use crate::identity::cache::Clock;

use super::TrustError;
use super::attestation::DidPublicKeyResolver;

// ---------------------------------------------------------------------------
// ChallengeType
// ---------------------------------------------------------------------------

/// The type of challenge to issue.
///
/// Standard challenge suites cover common capability categories. Custom
/// challenges allow context-specific verification.
///
/// See ADR-017 acceptance criterion 4.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChallengeType {
    /// Tests whether the subject resists prompt injection attacks.
    ///
    /// Parameters should include test prompts and expected behavior. The
    /// response result should indicate pass/fail for each injection vector.
    PromptInjectionResistance,

    /// Tests whether the subject correctly validates schemas.
    ///
    /// Parameters should include schemas and test payloads (both valid and
    /// invalid). The response result should indicate validation outcomes.
    SchemaValidation,

    /// Tests whether the subject complies with rate limits.
    ///
    /// Parameters should specify the rate limit and observation window. The
    /// response result should demonstrate that the subject stays within
    /// limits.
    RateLimitCompliance,

    /// A custom challenge type identified by a string key.
    ///
    /// Allows context-specific challenge definitions beyond the standard
    /// suites.
    Custom(String),
}

// ---------------------------------------------------------------------------
// ChallengeRequest
// ---------------------------------------------------------------------------

/// A challenge request for capability verification (ADR-017).
///
/// Issued by a challenger to verify a testable capability of the subject.
/// The request is signed by the challenger's Ed25519 key for authenticity.
///
/// See ADR-017 acceptance criterion 4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    /// Unique challenge identifier (UUID v4).
    pub challenge_id: String,

    /// The type of challenge being issued.
    pub challenge_type: ChallengeType,

    /// DID of the entity issuing the challenge.
    pub challenger_did: DID,

    /// DID of the entity being challenged.
    pub subject_did: DID,

    /// Challenge-specific parameters (schema, test vectors, limits, etc.).
    pub parameters: serde_json::Value,

    /// Maximum time allowed for the subject to respond.
    pub timeout: Duration,

    /// Ed25519 signature over the canonical challenge bytes.
    pub signature: Ed25519Signature,
}

// ---------------------------------------------------------------------------
// ChallengeResponse
// ---------------------------------------------------------------------------

/// A response to a challenge request (ADR-017).
///
/// Produced by the challenged subject after executing the challenge. The
/// response is signed by the responder's Ed25519 key.
///
/// See ADR-017 acceptance criterion 5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// The challenge ID this response corresponds to.
    pub challenge_id: String,

    /// DID of the entity responding to the challenge.
    pub responder_did: DID,

    /// Challenge-specific result data (pass/fail, metrics, evidence, etc.).
    pub result: serde_json::Value,

    /// Unix timestamp (seconds) when the response was completed.
    pub completed_at: u64,

    /// Ed25519 signature over the canonical response bytes.
    pub signature: Ed25519Signature,
}

// ---------------------------------------------------------------------------
// VerificationMethod
// ---------------------------------------------------------------------------

/// How a capability was verified.
///
/// Distinguishes self-attested claims from capabilities verified through the
/// challenge-response protocol. This metadata enables agents to weight
/// challenge-verified capabilities higher than self-attested ones in their
/// trust evaluation logic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationMethod {
    /// The capability was claimed by the subject without independent
    /// verification. Self-attested claims carry lower confidence.
    SelfAttested,

    /// The capability was verified through the challenge-response protocol.
    /// Includes the challenge type used for verification.
    ChallengeVerified {
        /// The type of challenge that was used to verify the capability.
        challenge_type: ChallengeType,
    },
}

// ---------------------------------------------------------------------------
// ChallengeVerification
// ---------------------------------------------------------------------------

/// The result of verifying a challenge response (ADR-017).
///
/// Produced by [`verify_challenge_response`]. Contains the verified challenge
/// and response data along with metadata about how the verification was
/// performed.
///
/// See ADR-017 acceptance criterion 5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeVerification {
    /// The challenge ID that was verified.
    pub challenge_id: String,

    /// DID of the challenger who issued the challenge.
    pub challenger_did: DID,

    /// DID of the responder who answered the challenge.
    pub responder_did: DID,

    /// The type of challenge that was verified.
    pub challenge_type: ChallengeType,

    /// The verification method: self-attested or challenge-verified.
    pub verification_method: VerificationMethod,

    /// The challenge-specific result from the response.
    pub result: serde_json::Value,

    /// Unix timestamp (seconds) when the response was completed.
    pub completed_at: u64,

    /// Unix timestamp (seconds) when the verification was performed.
    pub verified_at: u64,
}

// ---------------------------------------------------------------------------
// ChallengeSigner
// ---------------------------------------------------------------------------

/// Signs arbitrary bytes with an Ed25519 key.
///
/// Used by [`issue_challenge`] to sign challenge requests. Implementations
/// may delegate to a key custodian, HSM, or test fixture.
pub trait ChallengeSigner {
    /// Signs the given bytes and returns the Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if signing fails (e.g., key unavailable).
    fn sign(&self, data: &[u8]) -> Result<Ed25519Signature, TrustError>;
}

// ---------------------------------------------------------------------------
// Domain separators (issue #78)
// ---------------------------------------------------------------------------

/// Domain separator for challenge request canonical bytes.
const DOMAIN_CHALLENGE_REQ_V1: &[u8] = b"SCP-CHALLENGE-REQ-V1:";

/// Domain separator for challenge response canonical bytes.
const DOMAIN_CHALLENGE_RESP_V1: &[u8] = b"SCP-CHALLENGE-RESP-V1:";

// ---------------------------------------------------------------------------
// Canonical byte construction
// ---------------------------------------------------------------------------

/// Builds the canonical byte representation of a challenge request for signing.
///
/// The canonical form is: `"SCP-CHALLENGE-REQ-V1:" || challenge_id
/// || challenge_type || challenger_did || subject_did || parameters
/// || timeout_secs`. The domain separator prevents cross-protocol signature
/// confusion. This ensures signatures cover all semantically meaningful
/// fields.
fn canonical_challenge_request_bytes(request: &ChallengeRequest) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DOMAIN_CHALLENGE_REQ_V1);
    bytes.extend_from_slice(request.challenge_id.as_bytes());
    bytes.extend_from_slice(challenge_type_tag(&request.challenge_type).as_bytes());
    bytes.extend_from_slice(request.challenger_did.as_bytes());
    bytes.extend_from_slice(request.subject_did.as_bytes());

    // Deterministic JSON serialization for parameters.
    let params_bytes = serde_json::to_vec(&request.parameters).unwrap_or_default();
    bytes.extend_from_slice(&params_bytes);

    // Timeout as seconds (u64, big-endian).
    bytes.extend_from_slice(&request.timeout.as_secs().to_be_bytes());
    bytes
}

/// Builds the canonical byte representation of a challenge response for signing.
///
/// The canonical form is: `"SCP-CHALLENGE-RESP-V1:" || challenge_id
/// || responder_did || result || completed_at`. The domain separator
/// prevents cross-protocol signature confusion. This ensures signatures
/// cover all semantically meaningful fields.
fn canonical_challenge_response_bytes(response: &ChallengeResponse) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DOMAIN_CHALLENGE_RESP_V1);
    bytes.extend_from_slice(response.challenge_id.as_bytes());
    bytes.extend_from_slice(response.responder_did.as_bytes());

    // Deterministic JSON serialization for result.
    let result_bytes = serde_json::to_vec(&response.result).unwrap_or_default();
    bytes.extend_from_slice(&result_bytes);

    // completed_at as u64, big-endian.
    bytes.extend_from_slice(&response.completed_at.to_be_bytes());
    bytes
}

/// Returns a deterministic string tag for a challenge type.
fn challenge_type_tag(ct: &ChallengeType) -> String {
    match ct {
        ChallengeType::PromptInjectionResistance => "PromptInjectionResistance".to_owned(),
        ChallengeType::SchemaValidation => "SchemaValidation".to_owned(),
        ChallengeType::RateLimitCompliance => "RateLimitCompliance".to_owned(),
        ChallengeType::Custom(s) => format!("Custom:{s}"),
    }
}

// ---------------------------------------------------------------------------
// issue_challenge
// ---------------------------------------------------------------------------

/// Constructs and signs a challenge request.
///
/// Generates a unique challenge ID (UUID v4), builds the canonical byte
/// representation, signs it with the provided signer, and returns the
/// complete [`ChallengeRequest`].
///
/// # Parameters
///
/// - `challenger_did`: DID of the entity issuing the challenge.
/// - `subject_did`: DID of the entity being challenged.
/// - `challenge_type`: The type of challenge to issue.
/// - `params`: Challenge-specific parameters.
/// - `timeout`: Maximum time allowed for the subject to respond.
/// - `signer`: Signs the canonical challenge bytes.
///
/// # Errors
///
/// Returns [`TrustError`] if signing fails.
///
/// See ADR-017 acceptance criterion 4.
pub fn issue_challenge(
    challenger_did: DID,
    subject_did: DID,
    challenge_type: ChallengeType,
    params: serde_json::Value,
    timeout: Duration,
    signer: &impl ChallengeSigner,
) -> Result<ChallengeRequest, TrustError> {
    let challenge_id = uuid::Uuid::new_v4().to_string();

    // Build the request with an empty signature first so we can compute
    // canonical bytes, then replace the signature.
    let mut request = ChallengeRequest {
        challenge_id,
        challenge_type,
        challenger_did,
        subject_did,
        parameters: params,
        timeout,
        signature: vec![],
    };

    let canonical = canonical_challenge_request_bytes(&request);
    request.signature = signer.sign(&canonical)?;

    Ok(request)
}

// ---------------------------------------------------------------------------
// verify_challenge_response
// ---------------------------------------------------------------------------

/// Verifies a challenge response's signature and validates it against the
/// original challenge request.
///
/// # Verification steps
///
/// 1. **Challenge ID match:** The response's `challenge_id` must match the
///    request's `challenge_id`.
/// 2. **Responder identity:** The response's `responder_did` must match the
///    request's `subject_did` (the challenged entity must be the one
///    responding).
/// 3. **Timeout:** The response's `completed_at` must be within the
///    challenge's timeout window (relative to the current clock time minus
///    the timeout duration).
/// 4. **Signature:** Verifies the Ed25519 signature against the responder's
///    public key, resolved via the provided [`DidPublicKeyResolver`].
///
/// On success, returns a [`ChallengeVerification`] with
/// [`VerificationMethod::ChallengeVerified`].
///
/// # Errors
///
/// Returns specific [`TrustError`] variants for each failure mode:
/// - [`TrustError::ChallengeIdMismatch`] if IDs do not match
/// - [`TrustError::ChallengeResponderMismatch`] if responder is not the
///   challenged subject
/// - [`TrustError::ChallengeTimeout`] if the response arrived too late
/// - [`TrustError::ChallengeSignatureInvalid`] for signature failures
///
/// See ADR-017 acceptance criterion 5.
pub fn verify_challenge_response(
    request: &ChallengeRequest,
    response: &ChallengeResponse,
    resolver: &impl DidPublicKeyResolver,
    clock: &impl Clock,
) -> Result<ChallengeVerification, TrustError> {
    // 1. Challenge ID must match.
    if request.challenge_id != response.challenge_id {
        return Err(TrustError::ChallengeIdMismatch {
            expected: request.challenge_id.clone(),
            got: response.challenge_id.clone(),
        });
    }

    // 2. Responder must be the challenged subject.
    if request.subject_did != response.responder_did {
        return Err(TrustError::ChallengeResponderMismatch {
            expected: request.subject_did.to_string(),
            got: response.responder_did.to_string(),
        });
    }

    // 3. Check timeout: response must not have been completed after the
    //    deadline. We define the deadline as now (verification time).
    //    The completed_at must be within the timeout window relative to the
    //    current time, i.e., completed_at >= (now - timeout_secs).
    let now = clock.now();
    let timeout_secs = request.timeout.as_secs();
    if now > timeout_secs && response.completed_at < (now - timeout_secs) {
        return Err(TrustError::ChallengeTimeout {
            challenge_id: request.challenge_id.clone(),
            timeout_secs,
            completed_at: response.completed_at,
        });
    }

    // 4. Verify Ed25519 signature against responder's public key.
    let public_key_bytes = resolver.resolve_public_key(&response.responder_did)?;
    let canonical = canonical_challenge_response_bytes(response);
    verify_ed25519_signature(&public_key_bytes, &canonical, &response.signature).map_err(
        |reason| TrustError::ChallengeSignatureInvalid {
            challenge_id: request.challenge_id.clone(),
            reason,
        },
    )?;

    // Verification succeeded -- this is challenge-verified, not self-attested.
    Ok(ChallengeVerification {
        challenge_id: request.challenge_id.clone(),
        challenger_did: request.challenger_did.clone(),
        responder_did: response.responder_did.clone(),
        challenge_type: request.challenge_type.clone(),
        verification_method: VerificationMethod::ChallengeVerified {
            challenge_type: request.challenge_type.clone(),
        },
        result: response.result.clone(),
        completed_at: response.completed_at,
        verified_at: now,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::identity::cache::TestClock;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// A test resolver that maps DIDs to public key bytes.
    struct TestResolver {
        keys: HashMap<String, Vec<u8>>,
    }

    impl TestResolver {
        fn new() -> Self {
            Self {
                keys: HashMap::new(),
            }
        }

        fn add_key(&mut self, did: &str, public_key: Vec<u8>) {
            self.keys.insert(did.to_owned(), public_key);
        }
    }

    impl DidPublicKeyResolver for TestResolver {
        fn resolve_public_key(&self, did: &str) -> Result<Vec<u8>, TrustError> {
            self.keys
                .get(did)
                .cloned()
                .ok_or_else(|| TrustError::ChallengeSignatureInvalid {
                    challenge_id: String::new(),
                    reason: format!("DID not found: {did}"),
                })
        }
    }

    /// A test signer backed by an Ed25519 signing key.
    struct TestSigner {
        signing_key: SigningKey,
    }

    impl TestSigner {
        fn new(signing_key: SigningKey) -> Self {
            Self { signing_key }
        }
    }

    impl ChallengeSigner for TestSigner {
        fn sign(&self, data: &[u8]) -> Result<Ed25519Signature, TrustError> {
            let sig = self.signing_key.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
    }

    /// Creates a test signing key and returns (`signing_key`, `verifying_key_bytes`).
    fn test_keypair() -> (SigningKey, Vec<u8>) {
        let mut rng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key.to_bytes().to_vec())
    }

    /// Creates a signed challenge response for testing.
    fn make_signed_response(
        signing_key: &SigningKey,
        challenge_id: &str,
        responder_did: &str,
        result: serde_json::Value,
        completed_at: u64,
    ) -> ChallengeResponse {
        let mut response = ChallengeResponse {
            challenge_id: challenge_id.into(),
            responder_did: responder_did.into(),
            result,
            completed_at,
            signature: vec![],
        };

        let canonical = canonical_challenge_response_bytes(&response);
        let sig = signing_key.sign(&canonical);
        response.signature = sig.to_bytes().to_vec();
        response
    }

    // -----------------------------------------------------------------------
    // issue_challenge tests
    // -----------------------------------------------------------------------

    #[test]
    fn issue_challenge_constructs_signed_request() {
        let (challenger_key, _) = test_keypair();
        let signer = TestSigner::new(challenger_key);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::SchemaValidation,
            serde_json::json!({"schema": "test"}),
            Duration::from_secs(300),
            &signer,
        );

        assert!(request.is_ok(), "expected Ok, got {request:?}");
        let req = request.unwrap();
        assert!(!req.challenge_id.is_empty());
        assert_eq!(req.challenger_did, "did:key:challenger");
        assert_eq!(req.subject_did, "did:key:subject");
        assert_eq!(req.challenge_type, ChallengeType::SchemaValidation);
        assert_eq!(req.parameters, serde_json::json!({"schema": "test"}));
        assert_eq!(req.timeout, Duration::from_secs(300));
        assert_eq!(req.signature.len(), 64);
    }

    #[test]
    fn issue_challenge_generates_unique_ids() {
        let (challenger_key, _) = test_keypair();
        let signer = TestSigner::new(challenger_key);

        let r1 = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::PromptInjectionResistance,
            serde_json::json!({}),
            Duration::from_secs(60),
            &signer,
        )
        .unwrap();

        let r2 = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::PromptInjectionResistance,
            serde_json::json!({}),
            Duration::from_secs(60),
            &signer,
        )
        .unwrap();

        assert_ne!(r1.challenge_id, r2.challenge_id);
    }

    #[test]
    fn issue_challenge_supports_all_standard_suites() {
        let (challenger_key, _) = test_keypair();
        let signer = TestSigner::new(challenger_key);

        for ct in [
            ChallengeType::PromptInjectionResistance,
            ChallengeType::SchemaValidation,
            ChallengeType::RateLimitCompliance,
            ChallengeType::Custom("my-test".into()),
        ] {
            let result = issue_challenge(
                "did:key:c".into(),
                "did:key:s".into(),
                ct.clone(),
                serde_json::json!({}),
                Duration::from_secs(60),
                &signer,
            );
            assert!(result.is_ok(), "failed for {ct:?}: {result:?}");
            assert_eq!(result.unwrap().challenge_type, ct);
        }
    }

    // -----------------------------------------------------------------------
    // verify_challenge_response tests
    // -----------------------------------------------------------------------

    #[test]
    fn verify_challenge_response_succeeds_with_valid_response() {
        let (challenger_key, _) = test_keypair();
        let (subject_key, subject_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:subject", subject_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::SchemaValidation,
            serde_json::json!({"schema": "test"}),
            Duration::from_secs(300),
            &signer,
        )
        .unwrap();

        let response = make_signed_response(
            &subject_key,
            &request.challenge_id,
            "did:key:subject",
            serde_json::json!({"passed": true}),
            990,
        );

        let result = verify_challenge_response(&request, &response, &resolver, &clock);
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        let verification = result.unwrap();
        assert_eq!(verification.challenge_id, request.challenge_id);
        assert_eq!(verification.challenger_did, "did:key:challenger");
        assert_eq!(verification.responder_did, "did:key:subject");
        assert_eq!(verification.challenge_type, ChallengeType::SchemaValidation);
        assert_eq!(
            verification.verification_method,
            VerificationMethod::ChallengeVerified {
                challenge_type: ChallengeType::SchemaValidation
            }
        );
        assert_eq!(verification.result, serde_json::json!({"passed": true}));
        assert_eq!(verification.completed_at, 990);
        assert_eq!(verification.verified_at, 1000);
    }

    #[test]
    fn verify_challenge_response_distinguishes_challenge_verified() {
        let (challenger_key, _) = test_keypair();
        let (subject_key, subject_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:subject", subject_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::RateLimitCompliance,
            serde_json::json!({}),
            Duration::from_secs(600),
            &signer,
        )
        .unwrap();

        let response = make_signed_response(
            &subject_key,
            &request.challenge_id,
            "did:key:subject",
            serde_json::json!({"within_limits": true}),
            950,
        );

        let verification =
            verify_challenge_response(&request, &response, &resolver, &clock).unwrap();

        // Must be ChallengeVerified, not SelfAttested.
        assert_eq!(
            verification.verification_method,
            VerificationMethod::ChallengeVerified {
                challenge_type: ChallengeType::RateLimitCompliance
            }
        );
        assert_ne!(
            verification.verification_method,
            VerificationMethod::SelfAttested
        );
    }

    #[test]
    fn verify_challenge_response_rejects_mismatched_challenge_id() {
        let (challenger_key, _) = test_keypair();
        let (subject_key, subject_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:subject", subject_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::SchemaValidation,
            serde_json::json!({}),
            Duration::from_secs(300),
            &signer,
        )
        .unwrap();

        let response = make_signed_response(
            &subject_key,
            "wrong-challenge-id",
            "did:key:subject",
            serde_json::json!({}),
            990,
        );

        let result = verify_challenge_response(&request, &response, &resolver, &clock);
        assert!(result.is_err());
        match result {
            Err(TrustError::ChallengeIdMismatch { .. }) => {}
            other => panic!("expected ChallengeIdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_challenge_response_rejects_wrong_responder() {
        let (challenger_key, _) = test_keypair();
        let (imposter_key, imposter_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:imposter", imposter_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::SchemaValidation,
            serde_json::json!({}),
            Duration::from_secs(300),
            &signer,
        )
        .unwrap();

        // Response from imposter, not the challenged subject.
        let response = make_signed_response(
            &imposter_key,
            &request.challenge_id,
            "did:key:imposter",
            serde_json::json!({}),
            990,
        );

        let result = verify_challenge_response(&request, &response, &resolver, &clock);
        assert!(result.is_err());
        match result {
            Err(TrustError::ChallengeResponderMismatch { .. }) => {}
            other => panic!("expected ChallengeResponderMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_challenge_response_rejects_expired_response() {
        let (challenger_key, _) = test_keypair();
        let (subject_key, subject_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        // Clock is far ahead, response was completed long ago relative to timeout.
        let clock = TestClock::new(5000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:subject", subject_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::SchemaValidation,
            serde_json::json!({}),
            Duration::from_secs(60), // 60 second timeout
            &signer,
        )
        .unwrap();

        // Response completed at time 100, but clock is 5000 and timeout is 60.
        // Deadline check: 100 < (5000 - 60) = 4940 -> expired.
        let response = make_signed_response(
            &subject_key,
            &request.challenge_id,
            "did:key:subject",
            serde_json::json!({}),
            100,
        );

        let result = verify_challenge_response(&request, &response, &resolver, &clock);
        assert!(result.is_err());
        match result {
            Err(TrustError::ChallengeTimeout { .. }) => {}
            other => panic!("expected ChallengeTimeout, got {other:?}"),
        }
    }

    #[test]
    fn verify_challenge_response_accepts_response_within_timeout() {
        let (challenger_key, _) = test_keypair();
        let (subject_key, subject_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:subject", subject_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::PromptInjectionResistance,
            serde_json::json!({}),
            Duration::from_secs(300), // 5-minute timeout
            &signer,
        )
        .unwrap();

        // completed_at = 800, now = 1000, timeout = 300.
        // 800 >= (1000 - 300) = 700 -> within window.
        let response = make_signed_response(
            &subject_key,
            &request.challenge_id,
            "did:key:subject",
            serde_json::json!({"resistant": true}),
            800,
        );

        let result = verify_challenge_response(&request, &response, &resolver, &clock);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn verify_challenge_response_rejects_invalid_signature() {
        let (challenger_key, _) = test_keypair();
        let (subject_key, subject_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:subject", subject_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::SchemaValidation,
            serde_json::json!({}),
            Duration::from_secs(300),
            &signer,
        )
        .unwrap();

        let mut response = make_signed_response(
            &subject_key,
            &request.challenge_id,
            "did:key:subject",
            serde_json::json!({}),
            990,
        );

        // Corrupt the signature.
        response.signature[0] ^= 0xff;

        let result = verify_challenge_response(&request, &response, &resolver, &clock);
        assert!(result.is_err());
        match result {
            Err(TrustError::ChallengeSignatureInvalid { .. }) => {}
            other => panic!("expected ChallengeSignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_challenge_response_rejects_wrong_public_key() {
        let (challenger_key, _) = test_keypair();
        let (subject_key, _) = test_keypair();
        let (_, other_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        // Register a different key for the subject DID.
        resolver.add_key("did:key:subject", other_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::SchemaValidation,
            serde_json::json!({}),
            Duration::from_secs(300),
            &signer,
        )
        .unwrap();

        let response = make_signed_response(
            &subject_key,
            &request.challenge_id,
            "did:key:subject",
            serde_json::json!({}),
            990,
        );

        let result = verify_challenge_response(&request, &response, &resolver, &clock);
        assert!(result.is_err());
        match result {
            Err(TrustError::ChallengeSignatureInvalid { .. }) => {}
            other => panic!("expected ChallengeSignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_challenge_response_rejects_unresolvable_did() {
        let (challenger_key, _) = test_keypair();
        let (subject_key, _) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        // Empty resolver -- DID not registered.
        let resolver = TestResolver::new();

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::SchemaValidation,
            serde_json::json!({}),
            Duration::from_secs(300),
            &signer,
        )
        .unwrap();

        let response = make_signed_response(
            &subject_key,
            &request.challenge_id,
            "did:key:subject",
            serde_json::json!({}),
            990,
        );

        let result = verify_challenge_response(&request, &response, &resolver, &clock);
        assert!(result.is_err());
    }

    #[test]
    fn self_attested_differs_from_challenge_verified() {
        // Verify that the VerificationMethod enum correctly distinguishes
        // the two modes.
        let self_attested = VerificationMethod::SelfAttested;
        let challenge_verified = VerificationMethod::ChallengeVerified {
            challenge_type: ChallengeType::PromptInjectionResistance,
        };

        assert_ne!(self_attested, challenge_verified);

        // Different challenge types produce different verification methods.
        let verified_schema = VerificationMethod::ChallengeVerified {
            challenge_type: ChallengeType::SchemaValidation,
        };
        assert_ne!(challenge_verified, verified_schema);
    }

    #[test]
    fn challenge_type_custom_variant_preserves_key() {
        let ct = ChallengeType::Custom("my-custom-test".into());
        let tag = challenge_type_tag(&ct);
        assert_eq!(tag, "Custom:my-custom-test");
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let request = ChallengeRequest {
            challenge_id: "test-id".into(),
            challenge_type: ChallengeType::SchemaValidation,
            challenger_did: "did:key:c".into(),
            subject_did: "did:key:s".into(),
            parameters: serde_json::json!({"key": "value"}),
            timeout: Duration::from_secs(60),
            signature: vec![],
        };

        let bytes1 = canonical_challenge_request_bytes(&request);
        let bytes2 = canonical_challenge_request_bytes(&request);
        assert_eq!(bytes1, bytes2);

        let response = ChallengeResponse {
            challenge_id: "test-id".into(),
            responder_did: "did:key:s".into(),
            result: serde_json::json!({"ok": true}),
            completed_at: 1000,
            signature: vec![],
        };

        let rbytes1 = canonical_challenge_response_bytes(&response);
        let rbytes2 = canonical_challenge_response_bytes(&response);
        assert_eq!(rbytes1, rbytes2);
    }
}
