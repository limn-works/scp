//! Challenge-response protocol for trust verification.
//!
//! Enables verification of testable capabilities through a structured
//! challenge-response flow. Challenge types are identified by
//! [`CapabilityUri`] (ADR-041), unifying the previously separate
//! `ChallengeType` variants with the protocol capability registry.
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
//! See ADR-017 acceptance criteria 4-5 in `.docs/adrs/phase-4.md` and
//! ADR-041 acceptance criterion 3 for `ChallengeType` unification.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::crypto::ed25519::verify_ed25519_signature;
use scp_event_log::Ed25519Signature;
use scp_primitives::Clock;
use scp_primitives::DID;

use super::TrustError;
use super::attestation::DidPublicKeyResolver;
use super::capability_registry::{lookup_protocol_capability, validate_capability_uri};
use super::capability_uri::CapabilityUri;

// ---------------------------------------------------------------------------
// ChallengeType
// ---------------------------------------------------------------------------

/// The type of challenge to issue, identified by an [`CapabilityUri`].
///
/// Replaces the former enum variants (`PromptInjectionResistance`,
/// `SchemaValidation`, `RateLimitCompliance`, `Custom(String)`) with a
/// single URI-based variant per ADR-041 acceptance criterion 3.
///
/// # Legacy Mapping
///
/// | Old Variant                    | URI                                              |
/// |-------------------------------|--------------------------------------------------|
/// | `PromptInjectionResistance`    | `scp:capability:prompt-injection-resistance/v1`  |
/// | `SchemaValidation`             | `scp:capability:schema-validation/v1`            |
/// | `RateLimitCompliance`          | `scp:capability:rate-limit-compliance/v1`        |
/// | `Custom("name")`              | DID-scoped or protocol URI                       |
///
/// # Serialization
///
/// Serializes as the URI string. Deserializes from both URI strings and
/// legacy variant names (backwards-compatible).
///
/// See ADR-041 in `.docs/adrs/phase-4.md`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChallengeType {
    /// A challenge type identified by a validated capability URI.
    Uri(CapabilityUri),
}

impl ChallengeType {
    /// Creates a `ChallengeType` from a legacy variant name string.
    ///
    /// Maps the three former enum variant names to their protocol URIs:
    /// - `"PromptInjectionResistance"` → `scp:capability:prompt-injection-resistance/v1`
    /// - `"SchemaValidation"` → `scp:capability:schema-validation/v1`
    /// - `"RateLimitCompliance"` → `scp:capability:rate-limit-compliance/v1`
    ///
    /// Returns `None` for unrecognized legacy names.
    #[must_use]
    pub fn from_legacy(name: &str) -> Option<Self> {
        match name {
            "PromptInjectionResistance" => Some(Self::prompt_injection_resistance()),
            "SchemaValidation" => Some(Self::schema_validation()),
            "RateLimitCompliance" => Some(Self::rate_limit_compliance()),
            _ => None,
        }
    }

    /// Convenience constructor for prompt injection resistance challenges.
    #[must_use]
    pub fn prompt_injection_resistance() -> Self {
        Self::Uri(CapabilityUri::Protocol {
            name: "prompt-injection-resistance".to_owned(),
            version: 1,
        })
    }

    /// Convenience constructor for schema validation challenges.
    #[must_use]
    pub fn schema_validation() -> Self {
        Self::Uri(CapabilityUri::Protocol {
            name: "schema-validation".to_owned(),
            version: 1,
        })
    }

    /// Convenience constructor for rate limit compliance challenges.
    #[must_use]
    pub fn rate_limit_compliance() -> Self {
        Self::Uri(CapabilityUri::Protocol {
            name: "rate-limit-compliance".to_owned(),
            version: 1,
        })
    }

    /// Convenience constructor for tool integrity verification challenges.
    ///
    /// Used by [`verify_tool_integrity`](crate::context::tools::integrity::verify_tool_integrity)
    /// to produce [`ChallengeVerification`] results with a tool-integrity
    /// challenge type.
    #[must_use]
    pub fn tool_integrity() -> Self {
        Self::Uri(CapabilityUri::Protocol {
            name: "tool-integrity".to_owned(),
            version: 1,
        })
    }

    /// Returns a reference to the inner [`CapabilityUri`].
    #[must_use]
    pub const fn uri(&self) -> &CapabilityUri {
        let Self::Uri(uri) = self;
        uri
    }
}

// ---------------------------------------------------------------------------
// Serialize / Deserialize (backwards-compatible)
// ---------------------------------------------------------------------------

impl Serialize for ChallengeType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Self::Uri(uri) = self;
        serializer.serialize_str(&uri.to_string())
    }
}

impl<'de> Deserialize<'de> for ChallengeType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;

        // Try legacy variant names first (backwards compatibility).
        if let Some(ct) = Self::from_legacy(&s) {
            return Ok(ct);
        }

        // Try legacy Custom format: "Custom:name"
        if let Some(custom_name) = s.strip_prefix("Custom:") {
            // Legacy Custom strings that use scp:capability:* prefix must be
            // rejected — they would bypass registry validation.
            if custom_name.starts_with("scp:capability:") {
                return Err(serde::de::Error::custom(format!(
                    "legacy Custom string uses reserved scp:capability:* prefix: {custom_name}"
                )));
            }
            // Try to parse as a capability URI directly.
            if let Ok(uri) = custom_name.parse::<CapabilityUri>() {
                return Ok(Self::Uri(uri));
            }
            // Legacy unstructured custom strings can't be represented as
            // CapabilityUri — reject them.
            return Err(serde::de::Error::custom(format!(
                "legacy Custom string '{custom_name}' is not a valid capability URI"
            )));
        }

        // Try parsing as a capability URI.
        let uri: CapabilityUri = s.parse().map_err(serde::de::Error::custom)?;
        Ok(Self::Uri(uri))
    }
}

// ---------------------------------------------------------------------------
// ChallengeRequest
// ---------------------------------------------------------------------------

/// A challenge request for capability verification (ADR-017).
///
/// Issued by a challenger to verify a testable capability of the subject.
/// The request is signed by the challenger's Ed25519 key for authenticity.
///
/// See ADR-017 acceptance criterion 4, spec §7.3.4.
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

    /// The capability URI being tested (spec §7.3.4.1).
    ///
    /// Identifies which specific capability this challenge verifies, using the
    /// structured URI format: `scp:capability:{name}/v{N}` for protocol
    /// capabilities, or `did:{method}:{id}:capability:{name}/v{N}` for
    /// DID-scoped custom capabilities.
    pub capability_uri: String,

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
/// performed. A signed record that demonstrates a specific verifier tested
/// a capability and the agent passed — the verifier's signature prevents
/// forgery (spec §7.3.4.2).
///
/// See ADR-017 acceptance criterion 5, spec §7.3.4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeVerification {
    /// Unique verification identifier (derived from the challenge ID).
    #[serde(alias = "challenge_id")]
    pub verification_id: String,

    /// DID of the verifier who issued and verified the challenge.
    #[serde(alias = "challenger_did")]
    pub verifier_did: DID,

    /// DID of the subject who answered the challenge.
    #[serde(alias = "responder_did")]
    pub subject_did: DID,

    /// The capability URI that was verified (spec §7.3.4.1).
    pub capability_uri: String,

    /// The type of challenge that was verified.
    pub challenge_type: ChallengeType,

    /// The verification method: self-attested or challenge-verified.
    pub verification_method: VerificationMethod,

    /// Whether the subject passed the challenge overall.
    pub passed: bool,

    /// Optional numeric score (0–100) for graded challenges.
    pub score: Option<u32>,

    /// Total number of test cases in the challenge.
    pub test_count: u32,

    /// Number of test cases the subject passed.
    pub pass_count: u32,

    /// The challenge-specific result from the response.
    pub result: serde_json::Value,

    /// Unix timestamp (seconds) when the response was completed.
    pub completed_at: u64,

    /// Unix timestamp (seconds) when the verification was performed.
    pub verified_at: u64,

    /// Unix timestamp (seconds) when this verification expires.
    ///
    /// Challenges are repeatable (spec §7.3.4) — an expired verification
    /// means the capability should be re-challenged.
    pub expires_at: u64,

    /// Context in which the challenge was issued, if any.
    pub context_id: Option<String>,

    /// Ed25519 signature by the verifier over the verification record.
    ///
    /// Prevents forgery of verification results (spec §7.3.4.2).
    pub verifier_signature: Ed25519Signature,
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

/// Domain separator for challenge verification canonical bytes.
const DOMAIN_CHALLENGE_VERIFY_V1: &[u8] = b"SCP-CHALLENGE-VERIFY-V1:";

/// Default verification validity period: 90 days in seconds.
///
/// Challenges are repeatable (spec §7.3.4). After this period the
/// verification should be re-issued.
const DEFAULT_VERIFICATION_TTL_SECS: u64 = 90 * 24 * 3600;

/// Maximum tolerated clock skew (in seconds) for a challenge response's
/// `completed_at` timestamp relative to the verifier's clock.
///
/// A response claiming to have been completed meaningfully in the FUTURE is
/// implausible (the verifier cannot have observed a response that has not
/// happened yet) and is rejected — without this bound, the lower freshness
/// bound (`completed_at >= now - timeout`) could be evaded by stamping an
/// arbitrarily far-future `completed_at`. Set to 5 minutes to match the
/// protocol-wide clock-skew tolerance (spec §9.14).
const MAX_COMPLETION_FUTURE_SKEW_SECS: u64 = 5 * 60;

// ---------------------------------------------------------------------------
// Canonical byte construction
// ---------------------------------------------------------------------------

/// Builds the canonical byte representation of a challenge request for signing.
///
/// The canonical form is: `"SCP-CHALLENGE-REQ-V1:" || challenge_id
/// || challenge_type || challenger_did || subject_did || capability_uri
/// || parameters || timeout_secs`. The domain separator prevents
/// cross-protocol signature confusion. This ensures signatures cover all
/// semantically meaningful fields.
fn canonical_challenge_request_bytes(request: &ChallengeRequest) -> Result<Vec<u8>, TrustError> {
    use crate::crypto::canonical::{CanonicalField, canonical_hash_bytes};

    let type_tag = challenge_type_tag(&request.challenge_type);
    let params_bytes = crate::jcs::to_vec(&request.parameters).unwrap_or_default();

    canonical_hash_bytes(
        DOMAIN_CHALLENGE_REQ_V1,
        &[
            CanonicalField::VarBytes(request.challenge_id.as_bytes()),
            CanonicalField::VarBytes(type_tag.as_bytes()),
            CanonicalField::VarBytes(request.challenger_did.as_bytes()),
            CanonicalField::VarBytes(request.subject_did.as_bytes()),
            CanonicalField::VarBytes(request.capability_uri.as_bytes()),
            CanonicalField::VarBytes(&params_bytes),
            CanonicalField::U64(request.timeout.as_secs()),
        ],
    )
    .map_err(|e| TrustError::ChallengeSigningFailed {
        reason: format!("canonical hash failed: {e}"),
    })
}

/// Builds the canonical byte representation of a challenge response for signing.
///
/// The canonical form is: `"SCP-CHALLENGE-RESP-V1:" || challenge_id
/// || responder_did || result || completed_at`. The domain separator
/// prevents cross-protocol signature confusion. This ensures signatures
/// cover all semantically meaningful fields.
fn canonical_challenge_response_bytes(response: &ChallengeResponse) -> Result<Vec<u8>, TrustError> {
    use crate::crypto::canonical::{CanonicalField, canonical_hash_bytes};

    let result_bytes = crate::jcs::to_vec(&response.result).unwrap_or_default();

    canonical_hash_bytes(
        DOMAIN_CHALLENGE_RESP_V1,
        &[
            CanonicalField::VarBytes(response.challenge_id.as_bytes()),
            CanonicalField::VarBytes(response.responder_did.as_bytes()),
            CanonicalField::VarBytes(&result_bytes),
            CanonicalField::U64(response.completed_at),
        ],
    )
    .map_err(|e| TrustError::ChallengeSigningFailed {
        reason: format!("canonical hash failed: {e}"),
    })
}

/// Builds the canonical byte representation of a challenge verification for signing.
///
/// The canonical form is: `"SCP-CHALLENGE-VERIFY-V1:" || verification_id
/// || verifier_did || subject_did || capability_uri || challenge_type
/// || passed || score || test_count || pass_count || verified_at
/// || expires_at || context_id`.
/// The domain separator prevents cross-protocol signature confusion.
/// All fields including `score` and `context_id` are bound into the
/// signature to prevent post-signing modification.
///
/// Public (mirroring [`canonical_attestation_bytes`](super::canonical_attestation_bytes))
/// so verifiers can compute the exact bytes a `verifier_signature` covers — both
/// to mint a record (sign these bytes with the verifier key) and to independently
/// re-derive them when auditing one.
///
/// # Errors
///
/// Returns [`TrustError::CanonicalizationFailed`] if the canonical hash cannot be
/// constructed.
pub fn canonical_challenge_verification_bytes(
    verification: &ChallengeVerification,
) -> Result<Vec<u8>, TrustError> {
    use crate::crypto::canonical::{CanonicalField, canonical_hash_bytes};

    let type_tag = challenge_type_tag(&verification.challenge_type);

    let mut fields: Vec<CanonicalField<'_>> = vec![
        CanonicalField::VarBytes(verification.verification_id.as_bytes()),
        CanonicalField::VarBytes(verification.verifier_did.as_bytes()),
        CanonicalField::VarBytes(verification.subject_did.as_bytes()),
        CanonicalField::VarBytes(verification.capability_uri.as_bytes()),
        CanonicalField::VarBytes(type_tag.as_bytes()),
        CanonicalField::U8(u8::from(verification.passed)),
    ];

    // Score: present as U32, absent as sentinel.
    match verification.score {
        Some(s) => fields.push(CanonicalField::U32(s)),
        None => fields.push(CanonicalField::Absent),
    }

    fields.push(CanonicalField::U32(verification.test_count));
    fields.push(CanonicalField::U32(verification.pass_count));
    fields.push(CanonicalField::U64(verification.verified_at));
    fields.push(CanonicalField::U64(verification.expires_at));

    // Context ID: present as VarBytes, absent as sentinel.
    match &verification.context_id {
        Some(ctx) => fields.push(CanonicalField::VarBytes(ctx.as_bytes())),
        None => fields.push(CanonicalField::Absent),
    }

    canonical_hash_bytes(DOMAIN_CHALLENGE_VERIFY_V1, &fields).map_err(|e| {
        TrustError::CanonicalizationFailed {
            reason: format!("canonical hash failed: {e}"),
        }
    })
}

/// Returns the canonical URI string for a challenge type.
///
/// Used as the type tag in canonical byte construction for signatures.
fn challenge_type_tag(ct: &ChallengeType) -> String {
    let ChallengeType::Uri(uri) = ct;
    uri.to_string()
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
/// # Validation
///
/// Before constructing the request, validates the challenge type against the
/// protocol capability registry (§7.3.4.2):
///
/// - **Protocol capabilities** (`scp:capability:*`): must be registered in the
///   protocol registry. Unknown protocol URIs are rejected with
///   [`TrustError::UnknownChallengeCapability`].
/// - **DID-scoped capabilities** (`did:*`): always accepted without registry
///   lookup (authority is the definer's DID).
/// - **Parameter validation**: if the capability has a registered parameter
///   schema and parameters are non-null, validates the parameters against
///   the schema. Invalid parameters are rejected with
///   [`TrustError::InvalidChallengeParameters`].
///
/// # Parameters
///
/// - `challenger_did`: DID of the entity issuing the challenge.
/// - `subject_did`: DID of the entity being challenged.
/// - `challenge_type`: The type of challenge to issue.
/// - `capability_uri`: The capability URI being tested (spec §7.3.4.1).
/// - `params`: Challenge-specific parameters.
/// - `timeout`: Maximum time allowed for the subject to respond.
/// - `signer`: Signs the canonical challenge bytes.
///
/// # Errors
///
/// - [`TrustError::UnknownChallengeCapability`] if the challenge type is an
///   unknown `scp:capability:*` URI.
/// - [`TrustError::InvalidChallengeParameters`] if parameters fail schema
///   validation.
/// - [`TrustError`] if signing fails.
///
/// See ADR-017 acceptance criterion 4.
pub fn issue_challenge(
    challenger_did: DID,
    subject_did: DID,
    challenge_type: ChallengeType,
    capability_uri: String,
    params: serde_json::Value,
    timeout: Duration,
    signer: &impl ChallengeSigner,
) -> Result<ChallengeRequest, TrustError> {
    // Validate the challenge type against the capability registry.
    let ChallengeType::Uri(ref uri) = challenge_type;
    let uri_str = uri.to_string();

    // System capabilities (scp:system:*) are protocol feature flags, not
    // challenge-testable. Reject them before registry validation.
    if uri.is_system() {
        return Err(TrustError::NotChallengeable { uri: uri_str });
    }

    validate_capability_uri(&uri_str).map_err(|_| TrustError::UnknownChallengeCapability {
        uri: uri_str.clone(),
    })?;

    // If the capability has a parameter schema and parameters are non-null,
    // validate the parameters against the schema.
    if !params.is_null()
        && let Some(entry) = lookup_protocol_capability(&uri_str)
        && let Some(ref schema_value) = entry.parameter_schema
    {
        let validator = jsonschema::validator_for(schema_value).map_err(|e| {
            TrustError::InvalidChallengeParameters {
                uri: uri_str.clone(),
                reason: format!("failed to compile parameter schema: {e}"),
            }
        })?;
        if let Err(e) = validator.validate(&params) {
            return Err(TrustError::InvalidChallengeParameters {
                uri: uri_str,
                reason: e.to_string(),
            });
        }
    }

    let challenge_id = uuid::Uuid::new_v4().to_string();

    // Build the request with an empty signature first so we can compute
    // canonical bytes, then replace the signature.
    let mut request = ChallengeRequest {
        challenge_id,
        challenge_type,
        challenger_did,
        subject_did,
        capability_uri,
        parameters: params,
        timeout,
        signature: vec![],
    };

    let canonical = canonical_challenge_request_bytes(&request)?;
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
/// 3. **Freshness window:** The response's `completed_at` must be within the
///    challenge's timeout window (not older than `now - timeout`) AND not
///    implausibly in the future (not newer than `now + clock-skew tolerance`).
///    A far-future `completed_at` is rejected so it cannot evade the lower
///    staleness bound.
/// 4. **Signature:** Verifies the Ed25519 signature against the responder's
///    public key, resolved via the provided [`DidPublicKeyResolver`].
///
/// On success, returns a [`ChallengeVerification`] with
/// [`VerificationMethod::ChallengeVerified`], signed by the verifier.
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
/// See ADR-017 acceptance criterion 5, spec §7.3.4.
pub fn verify_challenge_response(
    request: &ChallengeRequest,
    response: &ChallengeResponse,
    resolver: &(impl DidPublicKeyResolver + ?Sized),
    clock: &(impl Clock + ?Sized),
    verifier_signer: &(impl ChallengeSigner + ?Sized),
    context_id: Option<String>,
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

    // 2b. Verify the request's own signature to detect tampering.
    //     A tampered request (e.g., extended timeout, changed subject_did)
    //     would pass steps 1-2 but produce a forged verification record.
    //     We resolve the challenger's public key and verify the request
    //     signature against the canonical request bytes.
    let challenger_pk = resolver.resolve_public_key(&request.challenger_did)?;
    let request_canonical = canonical_challenge_request_bytes(request)?;
    verify_ed25519_signature(&challenger_pk, &request_canonical, &request.signature)
        .map_err(|reason| TrustError::ChallengeRequestSignatureInvalid { reason })?;

    // 3. Check the freshness window: `completed_at` must fall within the
    //    acceptable band around the verifier's clock.
    //    - Lower bound: not older than the timeout, i.e.
    //      `completed_at >= now - timeout_secs`.
    //    - Upper bound: not implausibly in the future, i.e.
    //      `completed_at <= now + MAX_COMPLETION_FUTURE_SKEW_SECS`. Without this,
    //      a far-future `completed_at` trivially satisfies the lower bound and a
    //      stale/forged response could be replayed forever.
    let now = clock.now_secs();
    let timeout_secs = request.timeout.as_secs();
    let too_old = now > timeout_secs && response.completed_at < (now - timeout_secs);
    let too_far_future =
        response.completed_at > now.saturating_add(MAX_COMPLETION_FUTURE_SKEW_SECS);
    if too_old || too_far_future {
        return Err(TrustError::ChallengeTimeout {
            challenge_id: request.challenge_id.clone(),
            timeout_secs,
            completed_at: response.completed_at,
        });
    }

    // 4. Verify Ed25519 signature against responder's public key.
    let public_key_bytes = resolver.resolve_public_key(&response.responder_did)?;
    let canonical = canonical_challenge_response_bytes(response)?;
    verify_ed25519_signature(&public_key_bytes, &canonical, &response.signature).map_err(
        |reason| TrustError::ChallengeSignatureInvalid {
            challenge_id: request.challenge_id.clone(),
            reason,
        },
    )?;

    // Extract test_count/pass_count from result if present (sketch §7.3.4).
    #[allow(clippy::cast_possible_truncation)]
    // test/pass counts are small integers, safe to truncate
    let test_count = response
        .result
        .get("test_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as u32;
    #[allow(clippy::cast_possible_truncation)]
    // test/pass counts are small integers, safe to truncate
    let pass_count = response
        .result
        .get("pass_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as u32;
    let passed = response
        .result
        .get("passed")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(pass_count > 0 && pass_count == test_count);

    // Build the verification record (unsigned first, then sign).
    let mut verification = ChallengeVerification {
        verification_id: request.challenge_id.clone(),
        verifier_did: request.challenger_did.clone(),
        subject_did: response.responder_did.clone(),
        capability_uri: request.capability_uri.clone(),
        challenge_type: request.challenge_type.clone(),
        verification_method: VerificationMethod::ChallengeVerified {
            challenge_type: request.challenge_type.clone(),
        },
        passed,
        score: response
            .result
            .get("score")
            .and_then(serde_json::Value::as_u64)
            .map(|s| {
                #[allow(clippy::cast_possible_truncation)] // score values are small integers
                let truncated = s as u32;
                truncated
            }),
        test_count,
        pass_count,
        result: response.result.clone(),
        completed_at: response.completed_at,
        verified_at: now,
        expires_at: now + DEFAULT_VERIFICATION_TTL_SECS,
        context_id,
        verifier_signature: vec![],
    };

    // Sign the verification record (spec §7.3.4.2: verifier's signature
    // prevents forgery).
    let verify_canonical = canonical_challenge_verification_bytes(&verification)?;
    verification.verifier_signature = verifier_signer.sign(&verify_canonical)?;

    Ok(verification)
}

// ---------------------------------------------------------------------------
// verify_challenge_verification
// ---------------------------------------------------------------------------

/// Verifies the verifier's Ed25519 signature over a [`ChallengeVerification`]
/// record AND binds it to the target context and the current time.
///
/// A `ChallengeVerification` carries a caller-controlled `passed`/`score` trust
/// signal that is only trustworthy because the verifier signs it (spec
/// §7.3.4.2). The signature, produced by [`verify_challenge_response`], binds
/// every consumed field (`passed`, `score`, `expires_at`, `subject_did`,
/// `verifier_did`, `capability_uri`, `challenge_type`, `verified_at`,
/// `test_count`, `pass_count`, `context_id`) via
/// [`canonical_challenge_verification_bytes`], so a valid signature proves the
/// record was not forged or post-signing modified. This is the verify-on-ingest
/// gate for caller-supplied challenge results crossing the FFI boundary.
///
/// Beyond signature authenticity, this gate enforces the two bindings a
/// signature alone does NOT provide for a context-scoped store — a genuinely
/// verifier-signed result is still authentic when replayed into another context
/// or after it expires, so the signature does not stop replay:
///
/// 1. **Context binding.** The record's signed `context_id` must equal
///    `target_context_id`. A `None` (context-agnostic) result is REJECTED for a
///    context-scoped store, and a genuine result minted for context A cannot be
///    replayed into context B's aggregation
///    ([`TrustError::ChallengeContextMismatch`]).
/// 2. **Expiry.** Challenges are repeatable (spec §7.3.4); a record whose signed
///    `expires_at <= now` is REJECTED
///    ([`TrustError::ChallengeVerificationExpired`]) so a stale verification is
///    never consumed as a current trust signal. `now` is read from the injected
///    `clock`, matching the attestation ingest path.
///
/// # Errors
///
/// - [`TrustError`] from the resolver if the verifier's public key cannot be
///   resolved from `verifier_did`.
/// - [`TrustError::ChallengeVerificationSignatureInvalid`] if the signature does
///   not verify against the resolved verifier key.
/// - [`TrustError::ChallengeContextMismatch`] if the record's `context_id` is
///   not `Some(target_context_id)`.
/// - [`TrustError::ChallengeVerificationExpired`] if `expires_at <= now`.
pub fn verify_challenge_verification(
    verification: &ChallengeVerification,
    resolver: &(impl DidPublicKeyResolver + ?Sized),
    target_context_id: &str,
    clock: &(impl Clock + ?Sized),
) -> Result<(), TrustError> {
    let verifier_pk = resolver.resolve_public_key(&verification.verifier_did)?;
    let canonical = canonical_challenge_verification_bytes(verification)?;
    verify_ed25519_signature(&verifier_pk, &canonical, &verification.verifier_signature).map_err(
        |reason| TrustError::ChallengeVerificationSignatureInvalid {
            verification_id: verification.verification_id.clone(),
            reason,
        },
    )?;

    // Context binding: reject a `None` (context-agnostic) result for a
    // context-scoped store, and reject a genuine result minted for another
    // context. `context_id` is a signed field, so this comparison is over
    // authenticated data.
    if verification.context_id.as_deref() != Some(target_context_id) {
        return Err(TrustError::ChallengeContextMismatch {
            verification_id: verification.verification_id.clone(),
            record_context: verification.context_id.clone(),
            expected_context: target_context_id.to_owned(),
        });
    }

    // Expiry: challenges are repeatable; an expired verification is not a
    // current trust signal.
    let now = clock.now_secs();
    if verification.expires_at <= now {
        return Err(TrustError::ChallengeVerificationExpired {
            verification_id: verification.verification_id.clone(),
            expires_at: verification.expires_at,
            now,
        });
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
    use std::time::Duration;

    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use scp_primitives::TestClock;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Default capability URI for tests.
    const TEST_CAPABILITY_URI: &str = "scp:capability:schema-validation/v1";

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

        let canonical = canonical_challenge_response_bytes(&response).unwrap();
        let sig = signing_key.sign(&canonical);
        response.signature = sig.to_bytes().to_vec();
        response
    }

    // -----------------------------------------------------------------------
    // ChallengeType construction and from_legacy
    // -----------------------------------------------------------------------

    #[test]
    fn from_legacy_prompt_injection_resistance() {
        let ct = ChallengeType::from_legacy("PromptInjectionResistance").unwrap();
        assert_eq!(
            ct,
            ChallengeType::Uri(
                "scp:capability:prompt-injection-resistance/v1"
                    .parse()
                    .unwrap()
            )
        );
    }

    #[test]
    fn from_legacy_schema_validation() {
        let ct = ChallengeType::from_legacy("SchemaValidation").unwrap();
        assert_eq!(
            ct,
            ChallengeType::Uri("scp:capability:schema-validation/v1".parse().unwrap())
        );
    }

    #[test]
    fn from_legacy_rate_limit_compliance() {
        let ct = ChallengeType::from_legacy("RateLimitCompliance").unwrap();
        assert_eq!(
            ct,
            ChallengeType::Uri("scp:capability:rate-limit-compliance/v1".parse().unwrap())
        );
    }

    #[test]
    fn from_legacy_unknown_returns_none() {
        assert!(ChallengeType::from_legacy("Unknown").is_none());
    }

    #[test]
    fn convenience_constructors() {
        let pir = ChallengeType::prompt_injection_resistance();
        let sv = ChallengeType::schema_validation();
        let rlc = ChallengeType::rate_limit_compliance();

        assert_eq!(
            challenge_type_tag(&pir),
            "scp:capability:prompt-injection-resistance/v1"
        );
        assert_eq!(
            challenge_type_tag(&sv),
            "scp:capability:schema-validation/v1"
        );
        assert_eq!(
            challenge_type_tag(&rlc),
            "scp:capability:rate-limit-compliance/v1"
        );
    }

    #[test]
    fn uri_accessor() {
        let ct = ChallengeType::schema_validation();
        let uri = ct.uri();
        assert!(uri.is_protocol());
        assert_eq!(uri.name(), "schema-validation");
    }

    // -----------------------------------------------------------------------
    // Serialization / Deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn serialize_as_uri_string() {
        let ct = ChallengeType::schema_validation();
        let json = serde_json::to_string(&ct).unwrap();
        assert_eq!(json, "\"scp:capability:schema-validation/v1\"");
    }

    #[test]
    fn deserialize_from_uri_string() {
        let ct: ChallengeType =
            serde_json::from_str("\"scp:capability:schema-validation/v1\"").unwrap();
        assert_eq!(ct, ChallengeType::schema_validation());
    }

    #[test]
    fn deserialize_from_legacy_variant_name() {
        let ct: ChallengeType = serde_json::from_str("\"PromptInjectionResistance\"").unwrap();
        assert_eq!(ct, ChallengeType::prompt_injection_resistance());
    }

    #[test]
    fn deserialize_from_legacy_schema_validation() {
        let ct: ChallengeType = serde_json::from_str("\"SchemaValidation\"").unwrap();
        assert_eq!(ct, ChallengeType::schema_validation());
    }

    #[test]
    fn deserialize_from_legacy_rate_limit() {
        let ct: ChallengeType = serde_json::from_str("\"RateLimitCompliance\"").unwrap();
        assert_eq!(ct, ChallengeType::rate_limit_compliance());
    }

    #[test]
    fn deserialize_did_scoped_uri() {
        let ct: ChallengeType =
            serde_json::from_str("\"did:dht:z6Mk123:capability:custom-check/v1\"").unwrap();
        assert_eq!(
            ct,
            ChallengeType::Uri(
                "did:dht:z6Mk123:capability:custom-check/v1"
                    .parse()
                    .unwrap()
            )
        );
    }

    #[test]
    fn deserialize_rejects_unknown_protocol_uri() {
        // Unknown scp:capability:* URIs that parse fine syntactically should
        // still deserialize (validation is separate from parsing).
        let ct: ChallengeType = serde_json::from_str("\"scp:capability:nonexistent/v1\"").unwrap();
        assert_eq!(
            ct,
            ChallengeType::Uri("scp:capability:nonexistent/v1".parse().unwrap())
        );
    }

    #[test]
    fn deserialize_rejects_invalid_uri() {
        let result: Result<ChallengeType, _> = serde_json::from_str("\"not-a-uri\"");
        assert!(result.is_err());
    }

    #[test]
    fn serde_roundtrip() {
        let types = [
            ChallengeType::prompt_injection_resistance(),
            ChallengeType::schema_validation(),
            ChallengeType::rate_limit_compliance(),
            ChallengeType::Uri("did:dht:z6Mk123:capability:custom/v1".parse().unwrap()),
        ];
        for ct in &types {
            let json = serde_json::to_string(ct).unwrap();
            let deserialized: ChallengeType = serde_json::from_str(&json).unwrap();
            assert_eq!(ct, &deserialized, "roundtrip failed for {json}");
        }
    }

    // -----------------------------------------------------------------------
    // challenge_type_tag
    // -----------------------------------------------------------------------

    #[test]
    fn challenge_type_tag_returns_uri_string() {
        assert_eq!(
            challenge_type_tag(&ChallengeType::schema_validation()),
            "scp:capability:schema-validation/v1"
        );
        assert_eq!(
            challenge_type_tag(&ChallengeType::prompt_injection_resistance()),
            "scp:capability:prompt-injection-resistance/v1"
        );
        assert_eq!(
            challenge_type_tag(&ChallengeType::rate_limit_compliance()),
            "scp:capability:rate-limit-compliance/v1"
        );
    }

    #[test]
    fn challenge_type_tag_did_scoped() {
        let ct = ChallengeType::Uri("did:dht:z6Mk123:capability:custom/v1".parse().unwrap());
        assert_eq!(
            challenge_type_tag(&ct),
            "did:dht:z6Mk123:capability:custom/v1"
        );
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
            ChallengeType::schema_validation(),
            TEST_CAPABILITY_URI.to_owned(),
            serde_json::json!({"schema": "test"}),
            Duration::from_mins(5),
            &signer,
        );

        assert!(request.is_ok(), "expected Ok, got {request:?}");
        let req = request.unwrap();
        assert!(!req.challenge_id.is_empty());
        assert_eq!(req.challenger_did, "did:key:challenger");
        assert_eq!(req.subject_did, "did:key:subject");
        assert_eq!(req.challenge_type, ChallengeType::schema_validation());
        assert_eq!(req.capability_uri, TEST_CAPABILITY_URI);
        assert_eq!(req.parameters, serde_json::json!({"schema": "test"}));
        assert_eq!(req.timeout, Duration::from_mins(5));
        assert_eq!(req.signature.len(), 64);
    }

    #[test]
    fn issue_challenge_generates_unique_ids() {
        let (challenger_key, _) = test_keypair();
        let signer = TestSigner::new(challenger_key);

        let r1 = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::prompt_injection_resistance(),
            TEST_CAPABILITY_URI.to_owned(),
            serde_json::json!({}),
            Duration::from_mins(1),
            &signer,
        )
        .unwrap();

        let r2 = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::prompt_injection_resistance(),
            TEST_CAPABILITY_URI.to_owned(),
            serde_json::json!({}),
            Duration::from_mins(1),
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
            ChallengeType::prompt_injection_resistance(),
            ChallengeType::schema_validation(),
            ChallengeType::rate_limit_compliance(),
            ChallengeType::Uri("did:dht:z6Mk123:capability:custom/v1".parse().unwrap()),
        ] {
            let result = issue_challenge(
                "did:key:c".into(),
                "did:key:s".into(),
                ct.clone(),
                TEST_CAPABILITY_URI.to_owned(),
                serde_json::json!({}),
                Duration::from_mins(1),
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
        let (challenger_key, challenger_pubkey) = test_keypair();
        let (subject_key, subject_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:challenger", challenger_pubkey);
        resolver.add_key("did:key:subject", subject_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::schema_validation(),
            TEST_CAPABILITY_URI.to_owned(),
            serde_json::json!({"schema": "test"}),
            Duration::from_mins(5),
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

        let result =
            verify_challenge_response(&request, &response, &resolver, &clock, &signer, None);
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        let verification = result.unwrap();
        assert_eq!(verification.verification_id, request.challenge_id);
        assert_eq!(verification.verifier_did, "did:key:challenger");
        assert_eq!(verification.subject_did, "did:key:subject");
        assert_eq!(
            verification.challenge_type,
            ChallengeType::schema_validation()
        );
        assert_eq!(
            verification.verification_method,
            VerificationMethod::ChallengeVerified {
                challenge_type: ChallengeType::schema_validation()
            }
        );
        assert_eq!(verification.result, serde_json::json!({"passed": true}));
        assert_eq!(verification.completed_at, 990);
        assert_eq!(verification.verified_at, 1000);
    }

    #[test]
    fn verify_challenge_response_distinguishes_challenge_verified() {
        let (challenger_key, challenger_pubkey) = test_keypair();
        let (subject_key, subject_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:challenger", challenger_pubkey);
        resolver.add_key("did:key:subject", subject_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::rate_limit_compliance(),
            TEST_CAPABILITY_URI.to_owned(),
            serde_json::json!({}),
            Duration::from_mins(10),
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
            verify_challenge_response(&request, &response, &resolver, &clock, &signer, None)
                .unwrap();

        // Must be ChallengeVerified, not SelfAttested.
        assert_eq!(
            verification.verification_method,
            VerificationMethod::ChallengeVerified {
                challenge_type: ChallengeType::rate_limit_compliance()
            }
        );
        assert_ne!(
            verification.verification_method,
            VerificationMethod::SelfAttested
        );
    }

    #[test]
    fn verify_challenge_response_rejects_mismatched_challenge_id() {
        let (challenger_key, challenger_pubkey) = test_keypair();
        let (subject_key, subject_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:challenger", challenger_pubkey);
        resolver.add_key("did:key:subject", subject_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::schema_validation(),
            TEST_CAPABILITY_URI.to_owned(),
            serde_json::json!({}),
            Duration::from_mins(5),
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

        let result =
            verify_challenge_response(&request, &response, &resolver, &clock, &signer, None);
        assert!(result.is_err());
        match result {
            Err(TrustError::ChallengeIdMismatch { .. }) => {}
            other => panic!("expected ChallengeIdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_challenge_response_rejects_wrong_responder() {
        let (challenger_key, challenger_pubkey) = test_keypair();
        let (imposter_key, imposter_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:challenger", challenger_pubkey);
        resolver.add_key("did:key:imposter", imposter_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::schema_validation(),
            TEST_CAPABILITY_URI.to_owned(),
            serde_json::json!({}),
            Duration::from_mins(5),
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

        let result =
            verify_challenge_response(&request, &response, &resolver, &clock, &signer, None);
        assert!(result.is_err());
        match result {
            Err(TrustError::ChallengeResponderMismatch { .. }) => {}
            other => panic!("expected ChallengeResponderMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_challenge_response_rejects_expired_response() {
        let (challenger_key, challenger_pubkey) = test_keypair();
        let (subject_key, subject_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        // Clock is far ahead, response was completed long ago relative to timeout.
        let clock = TestClock::new(5000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:challenger", challenger_pubkey);
        resolver.add_key("did:key:subject", subject_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::schema_validation(),
            TEST_CAPABILITY_URI.to_owned(),
            serde_json::json!({}),
            Duration::from_mins(1), // 60 second timeout
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

        let result =
            verify_challenge_response(&request, &response, &resolver, &clock, &signer, None);
        assert!(result.is_err());
        match result {
            Err(TrustError::ChallengeTimeout { .. }) => {}
            other => panic!("expected ChallengeTimeout, got {other:?}"),
        }
    }

    #[test]
    fn verify_challenge_response_rejects_far_future_completed_at() {
        let (challenger_key, challenger_pubkey) = test_keypair();
        let (subject_key, subject_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:challenger", challenger_pubkey);
        resolver.add_key("did:key:subject", subject_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::schema_validation(),
            TEST_CAPABILITY_URI.to_owned(),
            serde_json::json!({}),
            Duration::from_mins(1),
            &signer,
        )
        .unwrap();

        // completed_at is far in the future (now = 1000, skew bound = 300s).
        // 1000 + 300 = 1300; completed_at = 100_000 is well past that, so the
        // upper freshness bound rejects it even though it trivially satisfies the
        // lower (staleness) bound.
        let response = make_signed_response(
            &subject_key,
            &request.challenge_id,
            "did:key:subject",
            serde_json::json!({}),
            100_000,
        );

        let result =
            verify_challenge_response(&request, &response, &resolver, &clock, &signer, None);
        match result {
            Err(TrustError::ChallengeTimeout { completed_at, .. }) => {
                assert_eq!(completed_at, 100_000);
            }
            other => panic!("expected ChallengeTimeout for far-future completed_at, got {other:?}"),
        }
    }

    #[test]
    fn verify_challenge_response_accepts_completed_at_within_future_skew() {
        let (challenger_key, challenger_pubkey) = test_keypair();
        let (subject_key, subject_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:challenger", challenger_pubkey);
        resolver.add_key("did:key:subject", subject_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::schema_validation(),
            TEST_CAPABILITY_URI.to_owned(),
            serde_json::json!({}),
            Duration::from_mins(5),
            &signer,
        )
        .unwrap();

        // completed_at slightly ahead of `now` (within the 300s skew tolerance):
        // 1000 + 60 = 1060 <= 1000 + 300, so a small benign skew is accepted.
        let response = make_signed_response(
            &subject_key,
            &request.challenge_id,
            "did:key:subject",
            serde_json::json!({}),
            1060,
        );

        let result =
            verify_challenge_response(&request, &response, &resolver, &clock, &signer, None);
        assert!(
            result.is_ok(),
            "expected Ok within skew tolerance, got {result:?}"
        );
    }

    #[test]
    fn verify_challenge_response_accepts_response_within_timeout() {
        let (challenger_key, challenger_pubkey) = test_keypair();
        let (subject_key, subject_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:challenger", challenger_pubkey);
        resolver.add_key("did:key:subject", subject_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::prompt_injection_resistance(),
            TEST_CAPABILITY_URI.to_owned(),
            serde_json::json!({}),
            Duration::from_mins(5), // 5-minute timeout
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

        let result =
            verify_challenge_response(&request, &response, &resolver, &clock, &signer, None);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn verify_challenge_response_rejects_invalid_signature() {
        let (challenger_key, challenger_pubkey) = test_keypair();
        let (subject_key, subject_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:challenger", challenger_pubkey);
        resolver.add_key("did:key:subject", subject_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::schema_validation(),
            TEST_CAPABILITY_URI.to_owned(),
            serde_json::json!({}),
            Duration::from_mins(5),
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

        let result =
            verify_challenge_response(&request, &response, &resolver, &clock, &signer, None);
        assert!(result.is_err());
        match result {
            Err(TrustError::ChallengeSignatureInvalid { .. }) => {}
            other => panic!("expected ChallengeSignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_challenge_response_rejects_wrong_public_key() {
        let (challenger_key, challenger_pubkey) = test_keypair();
        let (subject_key, _) = test_keypair();
        let (_, other_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:challenger", challenger_pubkey);
        // Register a different key for the subject DID.
        resolver.add_key("did:key:subject", other_pubkey);

        let request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::schema_validation(),
            TEST_CAPABILITY_URI.to_owned(),
            serde_json::json!({}),
            Duration::from_mins(5),
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

        let result =
            verify_challenge_response(&request, &response, &resolver, &clock, &signer, None);
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
            ChallengeType::schema_validation(),
            TEST_CAPABILITY_URI.to_owned(),
            serde_json::json!({}),
            Duration::from_mins(5),
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

        let result =
            verify_challenge_response(&request, &response, &resolver, &clock, &signer, None);
        assert!(result.is_err());
    }

    #[test]
    fn verify_challenge_response_rejects_tampered_request() {
        let (challenger_key, challenger_pubkey) = test_keypair();
        let (subject_key, subject_pubkey) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let clock = TestClock::new(1000);

        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:challenger", challenger_pubkey);
        resolver.add_key("did:key:subject", subject_pubkey);

        let mut request = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::schema_validation(),
            TEST_CAPABILITY_URI.to_owned(),
            serde_json::json!({}),
            Duration::from_mins(1),
            &signer,
        )
        .unwrap();

        // Tamper with the request: extend the timeout after signing.
        request.timeout = Duration::from_secs(9999);

        let response = make_signed_response(
            &subject_key,
            &request.challenge_id,
            "did:key:subject",
            serde_json::json!({"passed": true}),
            990,
        );

        let result =
            verify_challenge_response(&request, &response, &resolver, &clock, &signer, None);
        assert!(result.is_err());
        match result {
            Err(TrustError::ChallengeRequestSignatureInvalid { .. }) => {}
            other => panic!("expected ChallengeRequestSignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn self_attested_differs_from_challenge_verified() {
        // Verify that the VerificationMethod enum correctly distinguishes
        // the two modes.
        let self_attested = VerificationMethod::SelfAttested;
        let challenge_verified = VerificationMethod::ChallengeVerified {
            challenge_type: ChallengeType::prompt_injection_resistance(),
        };

        assert_ne!(self_attested, challenge_verified);

        // Different challenge types produce different verification methods.
        let verified_schema = VerificationMethod::ChallengeVerified {
            challenge_type: ChallengeType::schema_validation(),
        };
        assert_ne!(challenge_verified, verified_schema);
    }

    #[test]
    fn challenge_type_did_scoped_preserves_uri() {
        let ct = ChallengeType::Uri("did:dht:z6Mk123:capability:custom-test/v1".parse().unwrap());
        let tag = challenge_type_tag(&ct);
        assert_eq!(tag, "did:dht:z6Mk123:capability:custom-test/v1");
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let request = ChallengeRequest {
            challenge_id: "test-id".into(),
            challenge_type: ChallengeType::schema_validation(),
            challenger_did: "did:key:c".into(),
            subject_did: "did:key:s".into(),
            capability_uri: TEST_CAPABILITY_URI.to_owned(),
            parameters: serde_json::json!({"key": "value"}),
            timeout: Duration::from_mins(1),
            signature: vec![],
        };

        let bytes1 = canonical_challenge_request_bytes(&request).unwrap();
        let bytes2 = canonical_challenge_request_bytes(&request).unwrap();
        assert_eq!(bytes1, bytes2);

        let response = ChallengeResponse {
            challenge_id: "test-id".into(),
            responder_did: "did:key:s".into(),
            result: serde_json::json!({"ok": true}),
            completed_at: 1000,
            signature: vec![],
        };

        let rbytes1 = canonical_challenge_response_bytes(&response).unwrap();
        let rbytes2 = canonical_challenge_response_bytes(&response).unwrap();
        assert_eq!(rbytes1, rbytes2);
    }

    // -----------------------------------------------------------------------
    // Backwards-compatibility deserialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn deserialize_legacy_custom_with_did_scoped_uri() {
        // Legacy "Custom:did:dht:z6Mk:capability:x/v1" should deserialize.
        let ct: ChallengeType =
            serde_json::from_str("\"Custom:did:dht:z6Mk:capability:x/v1\"").unwrap();
        assert_eq!(
            ct,
            ChallengeType::Uri("did:dht:z6Mk:capability:x/v1".parse().unwrap())
        );
    }

    #[test]
    fn deserialize_legacy_custom_rejects_scp_capability_prefix() {
        // Legacy "Custom:scp:capability:..." should be rejected — it would
        // bypass registry validation.
        let result: Result<ChallengeType, _> =
            serde_json::from_str("\"Custom:scp:capability:fake/v1\"");
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_legacy_custom_rejects_unstructured_string() {
        // Legacy "Custom:my-custom-test" is not a valid capability URI.
        let result: Result<ChallengeType, _> = serde_json::from_str("\"Custom:my-custom-test\"");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // ChallengeType derives
    // -----------------------------------------------------------------------

    #[test]
    fn challenge_type_eq_and_hash() {
        use std::collections::HashSet;
        let a = ChallengeType::schema_validation();
        let b = ChallengeType::schema_validation();
        assert_eq!(a, b);

        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn challenge_type_clone_and_debug() {
        let ct = ChallengeType::schema_validation();
        let cloned = ct.clone();
        assert_eq!(ct, cloned);
        let debug = format!("{ct:?}");
        assert!(debug.contains("Uri"));
    }

    // -----------------------------------------------------------------------
    // issue_challenge — registry validation (SCP-ACR-004)
    // -----------------------------------------------------------------------

    /// Helper: issue a challenge with a given capability URI string and empty params.
    fn issue_with_uri(uri: &str) -> Result<ChallengeRequest, TrustError> {
        let (challenger_key, _) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let cap_uri: CapabilityUri = uri.parse().expect("test URI should parse");
        issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::Uri(cap_uri),
            uri.to_string(),
            serde_json::json!({}),
            Duration::from_mins(5),
            &signer,
        )
    }

    #[test]
    fn issue_challenge_accepts_safety_security_capability() {
        // prompt-injection-resistance from safety-security category
        let result = issue_with_uri("scp:capability:prompt-injection-resistance/v1");
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn issue_challenge_accepts_schema_compliance_capability() {
        // schema-validation from schema-compliance category
        let result = issue_with_uri("scp:capability:schema-validation/v1");
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn issue_challenge_accepts_behavioral_compliance_capability() {
        // rate-limit-compliance from behavioral-compliance category
        let result = issue_with_uri("scp:capability:rate-limit-compliance/v1");
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn issue_challenge_accepts_operational_capability() {
        // latency-compliance from operational category (parameterized)
        let (challenger_key, _) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let result = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::Uri("scp:capability:latency-compliance/v1".parse().unwrap()),
            "scp:capability:latency-compliance/v1".to_string(),
            serde_json::json!({"max_ms": 500}),
            Duration::from_mins(5),
            &signer,
        );
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn issue_challenge_accepts_spending_commerce_capability() {
        // spending-compliance from spending-commerce category
        let result = issue_with_uri("scp:capability:spending-compliance/v1");
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn issue_challenge_accepts_reasoning_logic_capability() {
        // mathematical-reasoning from reasoning-logic category (parameterized)
        let (challenger_key, _) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let result = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::Uri("scp:capability:mathematical-reasoning/v1".parse().unwrap()),
            "scp:capability:mathematical-reasoning/v1".to_string(),
            serde_json::json!({"difficulty": "intermediate"}),
            Duration::from_mins(5),
            &signer,
        );
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn issue_challenge_accepts_code_capability() {
        // code-generation from code category (parameterized)
        let (challenger_key, _) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let result = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::Uri("scp:capability:code-generation/v1".parse().unwrap()),
            "scp:capability:code-generation/v1".to_string(),
            serde_json::json!({"languages": ["rust", "python"]}),
            Duration::from_mins(5),
            &signer,
        );
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn issue_challenge_accepts_recall_fidelity_capability() {
        // instruction-retention from recall-fidelity category
        let result = issue_with_uri("scp:capability:instruction-retention/v1");
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn issue_challenge_accepts_bias_fairness_capability() {
        // bias-resistance from bias-fairness category
        let result = issue_with_uri("scp:capability:bias-resistance/v1");
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn issue_challenge_accepts_factual_hallucination_capability() {
        // source-attribution from factual-hallucination category
        let result = issue_with_uri("scp:capability:source-attribution/v1");
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn issue_challenge_accepts_did_scoped_custom_capability() {
        let result = issue_with_uri("did:dht:z6Mk123:capability:custom-skill/v1");
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn issue_challenge_rejects_unknown_protocol_capability() {
        let (challenger_key, _) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let cap_uri: CapabilityUri = "scp:capability:fake/v1".parse().unwrap();
        let result = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::Uri(cap_uri),
            "scp:capability:fake/v1".to_string(),
            serde_json::json!({}),
            Duration::from_mins(5),
            &signer,
        );
        assert!(result.is_err());
        match result {
            Err(TrustError::UnknownChallengeCapability { uri }) => {
                assert_eq!(uri, "scp:capability:fake/v1");
            }
            other => panic!("expected UnknownChallengeCapability, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // issue_challenge — parameter schema validation (SCP-ACR-004)
    // -----------------------------------------------------------------------

    #[test]
    fn issue_challenge_rejects_invalid_parameters_for_latency_compliance() {
        let (challenger_key, _) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        // latency-compliance requires {"max_ms": integer}, provide wrong type
        let result = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::Uri("scp:capability:latency-compliance/v1".parse().unwrap()),
            "scp:capability:latency-compliance/v1".to_string(),
            serde_json::json!({"max_ms": "not-an-integer"}),
            Duration::from_mins(5),
            &signer,
        );
        assert!(result.is_err());
        match result {
            Err(TrustError::InvalidChallengeParameters { uri, .. }) => {
                assert_eq!(uri, "scp:capability:latency-compliance/v1");
            }
            other => panic!("expected InvalidChallengeParameters, got {other:?}"),
        }
    }

    #[test]
    fn issue_challenge_rejects_missing_required_parameter() {
        let (challenger_key, _) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        // mathematical-reasoning requires {"difficulty": enum}, provide empty object
        let result = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::Uri("scp:capability:mathematical-reasoning/v1".parse().unwrap()),
            "scp:capability:mathematical-reasoning/v1".to_string(),
            serde_json::json!({"wrong_field": true}),
            Duration::from_mins(5),
            &signer,
        );
        assert!(result.is_err());
        match result {
            Err(TrustError::InvalidChallengeParameters { uri, .. }) => {
                assert_eq!(uri, "scp:capability:mathematical-reasoning/v1");
            }
            other => panic!("expected InvalidChallengeParameters, got {other:?}"),
        }
    }

    #[test]
    fn issue_challenge_accepts_null_params_for_parameterized_capability() {
        // Null parameters should skip schema validation (no params provided).
        let (challenger_key, _) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let result = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::Uri("scp:capability:latency-compliance/v1".parse().unwrap()),
            "scp:capability:latency-compliance/v1".to_string(),
            serde_json::Value::Null,
            Duration::from_mins(5),
            &signer,
        );
        assert!(
            result.is_ok(),
            "null params should skip schema validation, got {result:?}"
        );
    }

    #[test]
    fn issue_challenge_accepts_empty_params_for_non_parameterized_capability() {
        // Non-parameterized capabilities have no schema, so any params are fine.
        let (challenger_key, _) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let result = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::Uri(
                "scp:capability:prompt-injection-resistance/v1"
                    .parse()
                    .unwrap(),
            ),
            "scp:capability:prompt-injection-resistance/v1".to_string(),
            serde_json::json!({"test_vectors": ["attack1", "attack2"]}),
            Duration::from_mins(5),
            &signer,
        );
        assert!(
            result.is_ok(),
            "non-parameterized capability should accept any params, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // issue_challenge — system capability rejection (SCP-ACR-006)
    // -----------------------------------------------------------------------

    #[test]
    fn issue_challenge_rejects_system_capability() {
        let (challenger_key, _) = test_keypair();
        let signer = TestSigner::new(challenger_key);
        let cap_uri: CapabilityUri = "scp:system:relay-operation".parse().unwrap();
        let result = issue_challenge(
            "did:key:challenger".into(),
            "did:key:subject".into(),
            ChallengeType::Uri(cap_uri),
            "scp:system:relay-operation".to_string(),
            serde_json::json!({}),
            Duration::from_mins(5),
            &signer,
        );
        assert!(result.is_err());
        match result {
            Err(TrustError::NotChallengeable { uri }) => {
                assert_eq!(uri, "scp:system:relay-operation");
            }
            other => panic!("expected NotChallengeable, got {other:?}"),
        }
    }

    #[test]
    fn issue_challenge_rejects_all_system_capabilities() {
        let (challenger_key, _) = test_keypair();
        let signer = TestSigner::new(challenger_key);

        for system_uri in [
            "scp:system:mls-group-management",
            "scp:system:key-rotation",
            "scp:system:governance-participation",
            "scp:system:relay-operation",
            "scp:system:bridge-operation",
        ] {
            let cap_uri: CapabilityUri = system_uri.parse().unwrap();
            let result = issue_challenge(
                "did:key:challenger".into(),
                "did:key:subject".into(),
                ChallengeType::Uri(cap_uri),
                system_uri.to_string(),
                serde_json::json!({}),
                Duration::from_mins(5),
                &signer,
            );
            match result {
                Err(TrustError::NotChallengeable { uri }) => {
                    assert_eq!(uri, system_uri, "wrong URI in error for {system_uri}");
                }
                other => panic!("expected NotChallengeable for {system_uri}, got {other:?}"),
            }
        }
    }
}
