//! Challenge-response protocol for trust verification (spec 07 §7.3.4).
//!
//! A verifier tests a subject's claimed capability with test cases the
//! verifier writes. Each protocol capability URI defines a standard that
//! bounds the case count (§7.3.4.3); an identifier-scoped URI has none.
//!
//! # Flow
//!
//! 1. The verifier builds an [`UnsignedChallengeRequest`] with
//!    [`challenge_request_unsigned`], signs its [`signing_digest`] with its
//!    `#active` key, and attaches the signature with
//!    [`UnsignedChallengeRequest::with_verifier_signature`].
//! 2. The subject runs the cases and returns a signed [`ChallengeResponse`].
//! 3. The verifier checks the response with [`check_challenge_response`],
//!    signs the resulting [`UnsignedChallengeVerification`]'s digest, and
//!    publishes the [`ChallengeVerification`].
//! 4. A consumer verifies a record with [`verify_challenge_verification`].
//!
//! Signatures cover the 32-byte SHA-256 digest of each canonical preimage,
//! never the preimage itself.
//!
//! [`signing_digest`]: UnsignedChallengeRequest::signing_digest
//!
//! See ADR-017 acceptance criteria 4-5 in `.docs/adrs/phase-4.md` and
//! ADR-041 acceptance criterion 3 for `ChallengeType` unification.

use std::collections::{BTreeMap, HashSet};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use scp_clock::Clock;
use scp_crypto::verify_ed25519_signature;
use scp_did::DID;
use scp_event_log::Ed25519Signature;

use super::TrustError;
use super::attestation::DidPublicKeyResolver;
use super::capability_registry::{MinCases, lookup_protocol_capability, validate_capability_uri};
use super::capability_uri::CapabilityUri;
use super::language_tag::is_well_formed_language_tag;
use crate::crypto::canonical::{ABSENT_SENTINEL, CanonicalField, canonical_hash_bytes};

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
/// | `Custom("name")`              | identifier-scoped or protocol URI                |
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

    /// Convenience constructor for the `outlet-integrity/v1` challenge type.
    #[must_use]
    pub fn outlet_integrity() -> Self {
        Self::Uri(CapabilityUri::Protocol {
            name: "outlet-integrity".to_owned(),
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
// TestCase / ExpectedOutput
// ---------------------------------------------------------------------------

/// One test case of a challenge, written by the verifier (spec 07 §7.3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestCase {
    /// Identifier, unique within the request.
    pub test_id: String,
    /// JSON input given to the subject. It satisfies the I-JSON numeric
    /// constraint (`09-security-model.md` §9.5.2).
    pub input: serde_json::Value,
    /// What constitutes passing this case.
    pub expected: ExpectedOutput,
    /// Test category. For `scp:capability:multilingual/v1` it is a BCP 47
    /// language tag (§7.3.4.3).
    pub category: String,
    /// Importance weight in basis points; the request's weights sum to 10000.
    pub weight: u32,
}

/// What a test case's output must satisfy (spec 07 §7.3.4).
///
/// Serialized externally tagged: `{"<Variant>": {<fields>}}`, the wire form
/// the request preimage canonicalizes with RFC 8785.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpectedOutput {
    /// The output equals `value` (deep equality after JSON normalization).
    ExactMatch {
        /// The required output.
        value: serde_json::Value,
    },
    /// The output validates against `schema` (JSON Schema draft 2020-12).
    SchemaMatch {
        /// The JSON Schema the output must satisfy.
        schema: serde_json::Value,
    },
    /// Every string in `required` appears in the output's string form.
    ContainsAll {
        /// Strings that must all appear.
        required: Vec<String>,
    },
    /// No string in `forbidden` appears in the output's string form.
    ContainsNone {
        /// Strings that must not appear.
        forbidden: Vec<String>,
    },
    /// An evaluator outlet the challenger chooses scores the output; the SDK
    /// ships none.
    CustomEval {
        /// The evaluator outlet's identifier.
        evaluator_outlet_id: super::OutletId,
    },
}

// ---------------------------------------------------------------------------
// ChallengeRequest
// ---------------------------------------------------------------------------

/// A signed challenge request (spec 07 §7.3.4, ADR-017).
///
/// Every field except `verifier_signature` is covered by the signature, over
/// [`challenge_request_signing_digest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRequest {
    /// Random 32-byte challenge identifier, lowercase hex on the wire.
    #[serde(with = "crate::identity::scpid::hex_serde_32")]
    pub challenge_id: [u8; 32],

    /// The capability URI under test (spec 07 §7.3.4.1), in canonical form.
    pub capability_uri: String,

    /// The verifier-written test cases.
    pub test_cases: Vec<TestCase>,

    /// Maximum seconds the subject has to complete every case.
    pub timeout_secs: u32,

    /// The verifier's identifier, signed as its UTF-8 text. Spec 07 types it
    /// `Identifier` in the `03-identity.md` §3.1 text form; until SCP-308 an
    /// SDK identity prints only its did:dht string, which is what is carried.
    pub verifier: DID,

    /// The subject's identifier, with the same text-form caveat as `verifier`.
    pub subject: DID,

    /// The verifier's signature over [`challenge_request_signing_digest`].
    /// Spec 07 types it `P256Signature`; the code signs Ed25519 until the
    /// P-256 move, a code-lags-spec gap.
    pub verifier_signature: Ed25519Signature,
}

// ---------------------------------------------------------------------------
// ChallengeResponse
// ---------------------------------------------------------------------------

/// A response to a challenge request (ADR-017).
///
/// Produced by the challenged subject after executing the challenge and
/// signed by the subject's Ed25519 key over [`canonical_challenge_response_bytes`].
///
/// See ADR-017 acceptance criterion 5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// The challenge id this response answers: exactly
    /// `hex::encode(request.challenge_id)`, lowercase.
    pub challenge_id: String,

    /// DID of the entity responding to the challenge.
    pub responder_did: DID,

    /// The subject's result. [`check_challenge_response`] reads
    /// `test_count` and `pass_count` (unsigned 32-bit integers), `passed`
    /// (boolean) and, when present and not null, `score` (basis points,
    /// at most 10000).
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
/// challenge-response protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationMethod {
    /// The capability was claimed by the subject without independent
    /// verification. Self-attested claims carry lower confidence.
    SelfAttested,

    /// The capability was verified through the challenge-response protocol.
    ChallengeVerified {
        /// The type of challenge that was used to verify the capability.
        challenge_type: ChallengeType,
    },
}

// ---------------------------------------------------------------------------
// ChallengeVerification
// ---------------------------------------------------------------------------

/// A signed record proving a verifier tested a capability (spec 07 §7.3.4).
///
/// # Authenticated fields
///
/// The `verifier_signature` covers, in `R_v` order: `verification_id`,
/// `verifier`, `subject`, `capability_uri`, `suite_digest`, `passed`,
/// `score`, `test_count`, `pass_count`, `timestamp`, `expires_at` and
/// `context_id` (see [`canonical_challenge_verification_bytes`]).
///
/// `verification_method`, `result` and `completed_at` are NOT signed and can
/// be altered after signing without invalidating the record. No
/// authorization decision may read them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeVerification {
    /// `SHA-256(F(verifier) ‖ F(subject) ‖ F(capability_uri) ‖ timestamp)`
    /// ([`challenge_verification_id`]), lowercase hex on the wire.
    #[serde(with = "crate::identity::scpid::hex_serde_32")]
    pub verification_id: [u8; 32],

    /// The verifier, with the text-form caveat of [`ChallengeRequest::verifier`].
    pub verifier: DID,

    /// The subject, with the same caveat.
    pub subject: DID,

    /// The capability URI that was tested.
    pub capability_uri: String,

    /// SHA-256 of the scored request's `test_cases` encoding
    /// ([`challenge_suite_digest`]), lowercase hex on the wire.
    #[serde(with = "crate::identity::scpid::hex_serde_32")]
    pub suite_digest: [u8; 32],

    /// Whether the subject passed overall.
    pub passed: bool,

    /// Optional score in basis points, 0-10000 (10000 = perfect).
    pub score: Option<u32>,

    /// Number of test cases administered.
    pub test_count: u32,

    /// Number of test cases passed.
    pub pass_count: u32,

    /// Unix timestamp (seconds) of the verification.
    pub timestamp: u64,

    /// Unix timestamp (seconds) when the record expires; at most 90 days after
    /// `timestamp`.
    pub expires_at: u64,

    /// Context where the challenge was administered, if any.
    pub context_id: Option<String>,

    /// The verifier's signature over [`challenge_verification_signing_digest`].
    /// Spec 07 types it `P256Signature`; the code signs Ed25519 until the
    /// P-256 move, a code-lags-spec gap.
    pub verifier_signature: Ed25519Signature,

    /// Unsigned: how the capability was verified. No authorization decision
    /// may read it.
    pub verification_method: VerificationMethod,

    /// Unsigned: the subject's raw result. No authorization decision may read it.
    pub result: serde_json::Value,

    /// Unsigned: when the subject completed the response. No authorization
    /// decision may read it.
    pub completed_at: u64,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Domain separator of the challenge request preimage `R`. The encoding
/// changed under the same separator (spec 07 §7.3.4); no signature made
/// under the earlier encoding verifies.
const DOMAIN_CHALLENGE_REQ_V1: &[u8] = b"SCP-CHALLENGE-REQ-V1:";

/// Domain separator of the challenge response preimage.
const DOMAIN_CHALLENGE_RESP_V1: &[u8] = b"SCP-CHALLENGE-RESP-V1:";

/// Domain separator of the verification record preimage `R_v`. The encoding
/// changed under the same separator (spec 07 §7.3.4); no signature made
/// under the earlier encoding verifies.
const DOMAIN_CHALLENGE_VERIFY_V1: &[u8] = b"SCP-CHALLENGE-VERIFY-V1:";

/// Verification validity: 90 days, the spec 07 §7.3.4 maximum. A record
/// whose `expires_at` exceeds `timestamp` by more is rejected.
const DEFAULT_VERIFICATION_TTL_SECS: u64 = 90 * 24 * 3600;

/// The sum every request's test-case weights must reach (basis points).
const TOTAL_WEIGHT_BPS: u64 = 10_000;

/// The largest score a response may report (basis points).
const MAX_SCORE_BPS: u64 = 10_000;

/// Maximum tolerated clock skew (in seconds) for a challenge response's
/// `completed_at` timestamp relative to the verifier's clock.
///
/// A response claiming to have been completed meaningfully in the FUTURE is
/// implausible and is rejected; without this bound, the lower freshness
/// bound (`completed_at >= now - timeout`) could be evaded by stamping an
/// arbitrarily far-future `completed_at`. Set to 5 minutes to match the
/// protocol-wide clock-skew tolerance (spec §9.14).
///
/// Independent knob: shares the §9.14 5-minute default with
/// `crypto::ucan::validate::DEFAULT_CLOCK_SKEW_TOLERANCE_SECS`,
/// `envelope::validation::DEFAULT_CLOCK_SKEW_TOLERANCE_MS`, and
/// `trust::participation::MAX_PARTICIPATION_FUTURE_SKEW_SECS`, but is
/// deliberately a distinct constant, not unified.
const MAX_COMPLETION_FUTURE_SKEW_SECS: u64 = 5 * 60;

// ---------------------------------------------------------------------------
// Canonical encodings
// ---------------------------------------------------------------------------

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// RFC 8785 bytes of one suite JSON value, after the I-JSON check.
fn suite_json_bytes(
    value: &serde_json::Value,
    test_id: &str,
    field: &str,
) -> Result<Vec<u8>, TrustError> {
    crate::jcs::require_i_json(value).map_err(|v| TrustError::InvalidChallengeSuite {
        reason: format!("test case {test_id:?} {field}: {v}"),
    })?;
    crate::jcs::to_vec(value).map_err(|e| TrustError::ChallengeSigningFailed {
        reason: format!("test case {test_id:?} {field}: canonical JSON failed: {e}"),
    })
}

/// The `test_cases` field `T` of spec 07 §7.3.4.
///
/// A 4-byte BE count, then per case `test_id`, `JCS(input)`,
/// `JCS(expected wire form)`, `category` (each length-prefixed) and the 4-byte
/// BE `weight`. No domain separator.
///
/// # Errors
///
/// - [`TrustError::InvalidChallengeSuite`] if a case's `input` or `expected`
///   breaks the I-JSON numeric constraint, or the list has more than
///   `u32::MAX` cases.
/// - [`TrustError::ChallengeSigningFailed`] if canonical JSON fails.
pub fn test_cases_field_bytes(test_cases: &[TestCase]) -> Result<Vec<u8>, TrustError> {
    let count = u32::try_from(test_cases.len()).map_err(|_| TrustError::InvalidChallengeSuite {
        reason: format!("{} test cases exceed u32::MAX", test_cases.len()),
    })?;
    let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(test_cases.len());
    for case in test_cases {
        let expected = serde_json::to_value(&case.expected).map_err(|e| {
            TrustError::ChallengeSigningFailed {
                reason: format!(
                    "test case {:?} expected: serialization failed: {e}",
                    case.test_id
                ),
            }
        })?;
        encoded.push((
            suite_json_bytes(&case.input, &case.test_id, "input")?,
            suite_json_bytes(&expected, &case.test_id, "expected")?,
        ));
    }
    let mut fields = Vec::with_capacity(1 + 5 * test_cases.len());
    fields.push(CanonicalField::U32(count));
    for (case, (input, expected)) in test_cases.iter().zip(&encoded) {
        fields.extend([
            CanonicalField::VarBytes(case.test_id.as_bytes()),
            CanonicalField::VarBytes(input),
            CanonicalField::VarBytes(expected),
            CanonicalField::VarBytes(case.category.as_bytes()),
            CanonicalField::U32(case.weight),
        ]);
    }
    canonical_hash_bytes(b"", &fields).map_err(|e| TrustError::ChallengeSigningFailed {
        reason: format!("canonical test_cases encoding failed: {e}"),
    })
}

/// `suite_digest = SHA-256(T)` (spec 07 §7.3.4), with `T` from
/// [`test_cases_field_bytes`].
///
/// # Errors
///
/// As [`test_cases_field_bytes`].
pub fn challenge_suite_digest(test_cases: &[TestCase]) -> Result<[u8; 32], TrustError> {
    Ok(sha256(&test_cases_field_bytes(test_cases)?))
}

/// The request preimage `R` of spec 07 §7.3.4: `"SCP-CHALLENGE-REQ-V1:"`,
/// `challenge_id`, `capability_uri`, `T`, `timeout_secs`, `verifier`,
/// `subject`.
fn canonical_challenge_request_bytes(request: &ChallengeRequest) -> Result<Vec<u8>, TrustError> {
    let test_cases = test_cases_field_bytes(&request.test_cases)?;
    canonical_hash_bytes(
        DOMAIN_CHALLENGE_REQ_V1,
        &[
            CanonicalField::Fixed32(&request.challenge_id),
            CanonicalField::VarBytes(request.capability_uri.as_bytes()),
            CanonicalField::RawBytes(&test_cases),
            CanonicalField::U32(request.timeout_secs),
            CanonicalField::VarBytes(request.verifier.as_bytes()),
            CanonicalField::VarBytes(request.subject.as_bytes()),
        ],
    )
    .map_err(|e| TrustError::ChallengeSigningFailed {
        reason: format!("canonical hash failed: {e}"),
    })
}

/// The digest `D = SHA-256(R)` the verifier signs for a request.
///
/// # Errors
///
/// As [`test_cases_field_bytes`].
pub fn challenge_request_signing_digest(
    request: &ChallengeRequest,
) -> Result<[u8; 32], TrustError> {
    Ok(sha256(&canonical_challenge_request_bytes(request)?))
}

/// Builds the canonical bytes of a challenge response for signing.
///
/// `"SCP-CHALLENGE-RESP-V1:" || challenge_id || responder_did ||
/// JCS(result) || completed_at`. The subject signs these bytes directly.
///
/// # Errors
///
/// - [`TrustError::InvalidChallengeResponse`] if `result` breaks the I-JSON
///   numeric constraint (`09-security-model.md` §9.5.2): two distinct
///   integers above 2^53 canonicalize to the same bytes.
/// - [`TrustError::ChallengeSigningFailed`] if canonicalization fails.
pub fn canonical_challenge_response_bytes(
    response: &ChallengeResponse,
) -> Result<Vec<u8>, TrustError> {
    crate::jcs::require_i_json(&response.result).map_err(|v| {
        TrustError::InvalidChallengeResponse {
            challenge_id: response.challenge_id.clone(),
            reason: format!("result: {v}"),
        }
    })?;
    let result_bytes =
        crate::jcs::to_vec(&response.result).map_err(|e| TrustError::ChallengeSigningFailed {
            reason: format!("canonical result serialization failed: {e}"),
        })?;

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

/// `verification_id = SHA-256(F(verifier) ‖ F(subject) ‖ F(capability_uri) ‖
/// timestamp)` (spec 07 §7.3.4), `F` a 4-byte BE length plus UTF-8 and
/// `timestamp` 8-byte BE.
///
/// # Errors
///
/// [`TrustError::CanonicalizationFailed`] if a field exceeds `u32::MAX` bytes.
pub fn challenge_verification_id(
    verifier: &DID,
    subject: &DID,
    capability_uri: &str,
    timestamp: u64,
) -> Result<[u8; 32], TrustError> {
    let preimage = canonical_hash_bytes(
        b"",
        &[
            CanonicalField::VarBytes(verifier.as_bytes()),
            CanonicalField::VarBytes(subject.as_bytes()),
            CanonicalField::VarBytes(capability_uri.as_bytes()),
            CanonicalField::U64(timestamp),
        ],
    )
    .map_err(|e| TrustError::CanonicalizationFailed {
        reason: format!("verification_id preimage failed: {e}"),
    })?;
    Ok(sha256(&preimage))
}

/// The verification preimage `R_v` of spec 07 §7.3.4.
///
/// 12 fields in order: `verification_id`, `verifier`, `subject`, `capability_uri`,
/// `suite_digest`, `passed`, `score` (present `U32(4) ‖ U32(s)`, absent
/// `VarBytes(SHA-256(0x00))`), `test_count`, `pass_count`, `timestamp`,
/// `expires_at`, `context_id` (absent `VarBytes(SHA-256(0x00))`).
///
/// Public so an auditor can re-derive the exact bytes a record's digest
/// covers.
///
/// # Errors
///
/// [`TrustError::CanonicalizationFailed`] if the preimage cannot be built.
pub fn canonical_challenge_verification_bytes(
    verification: &ChallengeVerification,
) -> Result<Vec<u8>, TrustError> {
    let mut fields: Vec<CanonicalField<'_>> = vec![
        CanonicalField::Fixed32(&verification.verification_id),
        CanonicalField::VarBytes(verification.verifier.as_bytes()),
        CanonicalField::VarBytes(verification.subject.as_bytes()),
        CanonicalField::VarBytes(verification.capability_uri.as_bytes()),
        CanonicalField::Fixed32(&verification.suite_digest),
        CanonicalField::U8(u8::from(verification.passed)),
    ];
    match verification.score {
        Some(s) => fields.extend([CanonicalField::U32(4), CanonicalField::U32(s)]),
        None => fields.push(CanonicalField::VarBytes(&ABSENT_SENTINEL)),
    }
    fields.extend([
        CanonicalField::U32(verification.test_count),
        CanonicalField::U32(verification.pass_count),
        CanonicalField::U64(verification.timestamp),
        CanonicalField::U64(verification.expires_at),
    ]);
    fields.push(CanonicalField::VarBytes(
        verification
            .context_id
            .as_deref()
            .map_or(&ABSENT_SENTINEL[..], str::as_bytes),
    ));
    canonical_hash_bytes(DOMAIN_CHALLENGE_VERIFY_V1, &fields).map_err(|e| {
        TrustError::CanonicalizationFailed {
            reason: format!("canonical hash failed: {e}"),
        }
    })
}

/// The digest `D_v = SHA-256(R_v)` the verifier signs for a record.
///
/// # Errors
///
/// As [`canonical_challenge_verification_bytes`].
pub fn challenge_verification_signing_digest(
    verification: &ChallengeVerification,
) -> Result<[u8; 32], TrustError> {
    Ok(sha256(&canonical_challenge_verification_bytes(
        verification,
    )?))
}

// ---------------------------------------------------------------------------
// Unsigned request and record
// ---------------------------------------------------------------------------

/// A validated challenge request awaiting the verifier's signature.
///
/// Its digest is computed once at construction, from fields no caller can
/// change, so the digest a custody key signs is the digest of the request
/// [`with_verifier_signature`](Self::with_verifier_signature) returns.
#[derive(Debug, Clone)]
pub struct UnsignedChallengeRequest {
    request: ChallengeRequest,
    digest: [u8; 32],
}

impl UnsignedChallengeRequest {
    /// The digest `D` the verifier signs with its `#active` key.
    #[must_use]
    pub const fn signing_digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The request's random challenge id.
    #[must_use]
    pub const fn challenge_id(&self) -> [u8; 32] {
        self.request.challenge_id
    }

    /// Attaches the verifier's signature over [`signing_digest`](Self::signing_digest).
    #[must_use]
    pub fn with_verifier_signature(self, signature: Ed25519Signature) -> ChallengeRequest {
        ChallengeRequest {
            verifier_signature: signature,
            ..self.request
        }
    }
}

/// A checked verification record awaiting the verifier's signature.
///
/// Its digest is computed once at construction, like
/// [`UnsignedChallengeRequest`]'s.
#[derive(Debug, Clone)]
pub struct UnsignedChallengeVerification {
    verification: ChallengeVerification,
    digest: [u8; 32],
}

impl UnsignedChallengeVerification {
    /// The digest `D_v` the verifier signs with its `#active` key.
    #[must_use]
    pub const fn signing_digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The record to be signed; its `verifier_signature` is empty.
    #[must_use]
    pub const fn record(&self) -> &ChallengeVerification {
        &self.verification
    }

    /// Attaches the verifier's signature over [`signing_digest`](Self::signing_digest).
    #[must_use]
    pub fn with_verifier_signature(self, signature: Ed25519Signature) -> ChallengeVerification {
        ChallengeVerification {
            verifier_signature: signature,
            ..self.verification
        }
    }
}

// ---------------------------------------------------------------------------
// challenge_request_unsigned
// ---------------------------------------------------------------------------

/// Checks the suite rules of spec 07 §7.3.4 that hold for every URI: a
/// non-empty list of at most `u32::MAX` cases, unique `test_id`s, weights
/// summing to 10000, and I-JSON numbers in every `input` and `expected`.
fn check_suite_rules(test_cases: &[TestCase]) -> Result<u32, TrustError> {
    let invalid = |reason: String| TrustError::InvalidChallengeSuite { reason };
    if test_cases.is_empty() {
        return Err(invalid("test_cases is empty".to_owned()));
    }
    let count = u32::try_from(test_cases.len())
        .map_err(|_| invalid(format!("{} test cases exceed u32::MAX", test_cases.len())))?;
    let mut ids = HashSet::with_capacity(test_cases.len());
    let mut weight_sum: u64 = 0;
    for case in test_cases {
        if !ids.insert(case.test_id.as_str()) {
            return Err(invalid(format!("test_id {:?} repeats", case.test_id)));
        }
        weight_sum += u64::from(case.weight);
        let expected = serde_json::to_value(&case.expected).map_err(|e| {
            TrustError::ChallengeSigningFailed {
                reason: format!(
                    "test case {:?} expected: serialization failed: {e}",
                    case.test_id
                ),
            }
        })?;
        for (field, value) in [("input", &case.input), ("expected", &expected)] {
            crate::jcs::require_i_json(value)
                .map_err(|v| invalid(format!("test case {:?} {field}: {v}", case.test_id)))?;
        }
    }
    if weight_sum != TOTAL_WEIGHT_BPS {
        return Err(invalid(format!(
            "weights sum to {weight_sum}, not {TOTAL_WEIGHT_BPS}"
        )));
    }
    Ok(count)
}

/// Checks a protocol URI's minimum (spec 07 §7.3.4.3).
fn check_protocol_minimum(
    uri: &str,
    test_cases: &[TestCase],
    count: u32,
) -> Result<(), TrustError> {
    let standard = lookup_protocol_capability(uri)
        .and_then(|entry| entry.challenge)
        .ok_or_else(|| TrustError::NotChallengeable {
            uri: uri.to_owned(),
        })?;
    match standard.min_cases {
        MinCases::Total(minimum) => {
            if count < minimum {
                return Err(TrustError::ChallengeSuiteBelowMinimum {
                    uri: uri.to_owned(),
                    minimum,
                    supplied: count,
                    category: None,
                });
            }
        }
        MinCases::PerCategory(minimum) => {
            // Every category is a BCP 47 tag; tags differing only in ASCII
            // case name one language (RFC 5646 §2.1.1).
            let mut per_category: BTreeMap<String, u32> = BTreeMap::new();
            for case in test_cases {
                if !is_well_formed_language_tag(&case.category) {
                    return Err(TrustError::InvalidChallengeSuite {
                        reason: format!(
                            "test case {:?} category {:?} is not a well-formed BCP 47 language tag",
                            case.test_id, case.category
                        ),
                    });
                }
                *per_category
                    .entry(case.category.to_ascii_lowercase())
                    .or_insert(0) += 1;
            }
            if let Some((category, supplied)) = per_category.into_iter().find(|(_, n)| *n < minimum)
            {
                return Err(TrustError::ChallengeSuiteBelowMinimum {
                    uri: uri.to_owned(),
                    minimum,
                    supplied,
                    category: Some(category),
                });
            }
        }
    }
    Ok(())
}

/// Builds and validates a challenge request for the verifier to sign.
///
/// Checks, in order:
/// 1. `capability_uri` parses as a [`CapabilityUri`] in canonical form, else
///    [`TrustError::UnknownChallengeCapability`];
/// 2. a system URI is [`TrustError::NotChallengeable`];
/// 3. [`validate_capability_uri`] accepts it, else
///    [`TrustError::UnknownChallengeCapability`];
/// 4. the suite rules, else [`TrustError::InvalidChallengeSuite`]: a
///    non-empty list, unique `test_id`s, weights summing to 10000, and no
///    integer of magnitude above 2^53 or non-finite number in any `input` or
///    `expected`;
/// 5. for a protocol URI, its standard's minimum (spec 07 §7.3.4.3), else
///    [`TrustError::ChallengeSuiteBelowMinimum`]. For `multilingual/v1` each
///    `category` must also be a well-formed BCP 47 tag
///    ([`TrustError::InvalidChallengeSuite`]). Identifier-scoped URIs have no
///    protocol minimum.
///
/// The 32-byte `challenge_id` is drawn from the OS random source.
///
/// # Errors
///
/// The errors above, and [`TrustError::ChallengeSigningFailed`] if the OS
/// random source fails or canonical encoding fails.
pub fn challenge_request_unsigned(
    verifier: DID,
    subject: DID,
    capability_uri: String,
    test_cases: Vec<TestCase>,
    timeout_secs: u32,
) -> Result<UnsignedChallengeRequest, TrustError> {
    let uri: CapabilityUri =
        capability_uri
            .parse()
            .map_err(|_| TrustError::UnknownChallengeCapability {
                uri: capability_uri.clone(),
            })?;
    if uri.is_system() {
        return Err(TrustError::NotChallengeable {
            uri: capability_uri,
        });
    }
    validate_capability_uri(&capability_uri).map_err(|_| {
        TrustError::UnknownChallengeCapability {
            uri: capability_uri.clone(),
        }
    })?;
    let count = check_suite_rules(&test_cases)?;
    if matches!(uri, CapabilityUri::Protocol { .. }) {
        check_protocol_minimum(&capability_uri, &test_cases, count)?;
    }

    let mut challenge_id = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut challenge_id)
        .map_err(|e| TrustError::ChallengeSigningFailed {
            reason: format!("OS random source failed: {e}"),
        })?;

    let request = ChallengeRequest {
        challenge_id,
        capability_uri,
        test_cases,
        timeout_secs,
        verifier,
        subject,
        verifier_signature: Vec::new(),
    };
    let digest = challenge_request_signing_digest(&request)?;
    Ok(UnsignedChallengeRequest { request, digest })
}

// ---------------------------------------------------------------------------
// check_challenge_response
// ---------------------------------------------------------------------------

/// The counts a response's `result` reports (self-reported until scoring
/// against `expected` lands).
struct ReportedCounts {
    passed: bool,
    score: Option<u32>,
    test_count: u32,
    pass_count: u32,
}

/// Reads the counts from a response's `result`. Every field is required and
/// typed; nothing defaults.
fn reported_counts(response: &ChallengeResponse) -> Result<ReportedCounts, TrustError> {
    let invalid = |reason: &str| TrustError::InvalidChallengeResponse {
        challenge_id: response.challenge_id.clone(),
        reason: reason.to_owned(),
    };
    let result = &response.result;
    let read_u32 = |key: &str| {
        result
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| {
                invalid(&format!(
                    "result.{key} is missing or not an unsigned 32-bit integer"
                ))
            })
    };
    let test_count = read_u32("test_count")?;
    let pass_count = read_u32("pass_count")?;
    let passed = result
        .get("passed")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| invalid("result.passed is missing or not a boolean"))?;
    let score = match result.get("score") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => {
            let s = value
                .as_u64()
                .filter(|s| *s <= MAX_SCORE_BPS)
                .ok_or_else(|| invalid("result.score is not an integer from 0 to 10000"))?;
            Some(u32::try_from(s).map_err(|_| invalid("result.score exceeds u32"))?)
        }
    };
    Ok(ReportedCounts {
        passed,
        score,
        test_count,
        pass_count,
    })
}

/// Checks a subject's response against the verifier's own signed request and
/// builds the verification record for the verifier to sign.
///
/// Steps, in order:
/// 0. `request.verifier` is `verifier`, else
///    [`TrustError::ChallengeVerifierMismatch`];
/// 1. `response.challenge_id == hex::encode(request.challenge_id)` exactly
///    (lowercase), else [`TrustError::ChallengeIdMismatch`];
/// 2. `response.responder_did == request.subject`, else
///    [`TrustError::ChallengeResponderMismatch`];
/// 3. the request's `verifier_signature` verifies over
///    [`challenge_request_signing_digest`] against `request.verifier`'s key,
///    else [`TrustError::ChallengeRequestSignatureInvalid`];
/// 4. `completed_at` is no older than `timeout_secs` and no more than
///    5 minutes ahead of the clock, else [`TrustError::ChallengeTimeout`];
/// 5. the response signature verifies over
///    [`canonical_challenge_response_bytes`] against the subject's key, else
///    [`TrustError::ChallengeSignatureInvalid`];
/// 6. the result reports `test_count` equal to the request's case count,
///    `pass_count <= test_count`, and any `score <= 10000`, else
///    [`TrustError::InvalidChallengeResponse`].
///
/// The record carries `timestamp = clock.now_secs()`, the derived
/// `verification_id`, `expires_at = timestamp + 90 days`,
/// `context_id = Some(context_id)` and the request's `suite_digest`.
///
/// # Errors
///
/// The errors above; a resolver error (for example
/// [`TrustError::KeyResolutionUnavailable`]) propagates unchanged.
pub fn check_challenge_response(
    request: &ChallengeRequest,
    response: &ChallengeResponse,
    resolver: &(impl DidPublicKeyResolver + ?Sized),
    clock: &(impl Clock + ?Sized),
    verifier: &DID,
    context_id: String,
) -> Result<UnsignedChallengeVerification, TrustError> {
    if request.verifier != *verifier {
        return Err(TrustError::ChallengeVerifierMismatch {
            expected: request.verifier.to_string(),
            got: verifier.to_string(),
        });
    }

    let challenge_id = hex::encode(request.challenge_id);
    if response.challenge_id != challenge_id {
        return Err(TrustError::ChallengeIdMismatch {
            expected: challenge_id,
            got: response.challenge_id.clone(),
        });
    }

    if request.subject != response.responder_did {
        return Err(TrustError::ChallengeResponderMismatch {
            expected: request.subject.to_string(),
            got: response.responder_did.to_string(),
        });
    }

    let verifier_pk = resolver.resolve_public_key(&request.verifier)?;
    let request_digest = challenge_request_signing_digest(request)?;
    verify_ed25519_signature(&verifier_pk, &request_digest, &request.verifier_signature)
        .map_err(|reason| TrustError::ChallengeRequestSignatureInvalid { reason })?;

    let now = clock.now_secs();
    let timeout_secs = u64::from(request.timeout_secs);
    let too_old = response.completed_at < now.saturating_sub(timeout_secs);
    let too_far_future =
        response.completed_at > now.saturating_add(MAX_COMPLETION_FUTURE_SKEW_SECS);
    if too_old || too_far_future {
        return Err(TrustError::ChallengeTimeout {
            challenge_id,
            timeout_secs,
            completed_at: response.completed_at,
        });
    }

    let subject_pk = resolver.resolve_public_key(&response.responder_did)?;
    let response_bytes = canonical_challenge_response_bytes(response)?;
    verify_ed25519_signature(&subject_pk, &response_bytes, &response.signature).map_err(
        |reason| TrustError::ChallengeSignatureInvalid {
            challenge_id: challenge_id.clone(),
            reason,
        },
    )?;

    let counts = reported_counts(response)?;
    let invalid = |reason: String| TrustError::InvalidChallengeResponse {
        challenge_id: challenge_id.clone(),
        reason,
    };
    let case_count = request.test_cases.len();
    if usize::try_from(counts.test_count).ok() != Some(case_count) {
        return Err(invalid(format!(
            "test_count {} is not the request's {case_count} test cases",
            counts.test_count
        )));
    }
    if counts.pass_count > counts.test_count {
        return Err(invalid(format!(
            "pass_count {} exceeds test_count {}",
            counts.pass_count, counts.test_count
        )));
    }

    let uri = validate_capability_uri(&request.capability_uri).map_err(|_| {
        TrustError::UnknownChallengeCapability {
            uri: request.capability_uri.clone(),
        }
    })?;
    let timestamp = now;
    let expires_at = timestamp
        .checked_add(DEFAULT_VERIFICATION_TTL_SECS)
        .ok_or_else(|| invalid(format!("timestamp {timestamp} overflows expires_at")))?;
    let verification = ChallengeVerification {
        verification_id: challenge_verification_id(
            &request.verifier,
            &request.subject,
            &request.capability_uri,
            timestamp,
        )?,
        verifier: request.verifier.clone(),
        subject: request.subject.clone(),
        capability_uri: request.capability_uri.clone(),
        suite_digest: challenge_suite_digest(&request.test_cases)?,
        passed: counts.passed,
        score: counts.score,
        test_count: counts.test_count,
        pass_count: counts.pass_count,
        timestamp,
        expires_at,
        context_id: Some(context_id),
        verifier_signature: Vec::new(),
        verification_method: VerificationMethod::ChallengeVerified {
            challenge_type: ChallengeType::Uri(uri),
        },
        result: response.result.clone(),
        completed_at: response.completed_at,
    };
    let digest = challenge_verification_signing_digest(&verification)?;
    Ok(UnsignedChallengeVerification {
        verification,
        digest,
    })
}

// ---------------------------------------------------------------------------
// Test-only signing conveniences
// ---------------------------------------------------------------------------

/// Signs a 32-byte digest with an Ed25519 key. Test and fixture use only;
/// production signs through the verifier's custody.
#[cfg(any(test, feature = "testing"))]
pub trait ChallengeSigner {
    /// Signs `digest` and returns the Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if signing fails.
    fn sign(&self, digest: &[u8; 32]) -> Result<Ed25519Signature, TrustError>;
}

/// [`challenge_request_unsigned`] followed by signing its digest with
/// `signer`. Test and fixture use only.
///
/// # Errors
///
/// As [`challenge_request_unsigned`], or the signer's error.
#[cfg(any(test, feature = "testing"))]
pub fn issue_challenge(
    verifier: DID,
    subject: DID,
    capability_uri: String,
    test_cases: Vec<TestCase>,
    timeout_secs: u32,
    signer: &(impl ChallengeSigner + ?Sized),
) -> Result<ChallengeRequest, TrustError> {
    let unsigned =
        challenge_request_unsigned(verifier, subject, capability_uri, test_cases, timeout_secs)?;
    let signature = signer.sign(&unsigned.signing_digest())?;
    Ok(unsigned.with_verifier_signature(signature))
}

/// [`check_challenge_response`] followed by signing the record's digest with
/// `verifier_signer`. Test and fixture use only.
///
/// # Errors
///
/// As [`check_challenge_response`], or the signer's error.
#[cfg(any(test, feature = "testing"))]
pub fn verify_challenge_response(
    request: &ChallengeRequest,
    response: &ChallengeResponse,
    resolver: &(impl DidPublicKeyResolver + ?Sized),
    clock: &(impl Clock + ?Sized),
    verifier_signer: &(impl ChallengeSigner + ?Sized),
    verifier: &DID,
    context_id: String,
) -> Result<ChallengeVerification, TrustError> {
    let unsigned =
        check_challenge_response(request, response, resolver, clock, verifier, context_id)?;
    let signature = verifier_signer.sign(&unsigned.signing_digest())?;
    Ok(unsigned.with_verifier_signature(signature))
}

// ---------------------------------------------------------------------------
// verify_challenge_verification
// ---------------------------------------------------------------------------

/// Verifies a [`ChallengeVerification`] record and binds it to a subject, a
/// context and the current time. This is the verify-on-ingest gate for
/// caller-supplied records.
///
/// Checks, in order:
/// 1. the `verifier_signature` verifies over
///    [`challenge_verification_signing_digest`] against the `verifier`'s key,
///    else [`TrustError::ChallengeVerificationSignatureInvalid`];
/// 2. `verification_id` equals [`challenge_verification_id`] of the record's
///    fields, else [`TrustError::ChallengeVerificationIdMismatch`];
/// 3. `expires_at - timestamp` is at most 90 days, else
///    [`TrustError::ChallengeVerificationValidityTooLong`];
/// 4. the signed `subject` is `expected_subject`, else
///    [`TrustError::ChallengeSubjectMismatch`];
/// 5. the signed `context_id` is `Some(target_context_id)`, else
///    [`TrustError::ChallengeContextMismatch`]; a genuine record minted for
///    another context, or for none, is not replayable here;
/// 6. `expires_at > now`, else [`TrustError::ChallengeVerificationExpired`].
///
/// # Errors
///
/// The errors above; a resolver error propagates unchanged.
pub fn verify_challenge_verification(
    verification: &ChallengeVerification,
    resolver: &(impl DidPublicKeyResolver + ?Sized),
    target_context_id: &str,
    expected_subject: &str,
    clock: &(impl Clock + ?Sized),
) -> Result<(), TrustError> {
    let id_hex = hex::encode(verification.verification_id);
    let verifier_pk = resolver.resolve_public_key(&verification.verifier)?;
    let digest = challenge_verification_signing_digest(verification)?;
    verify_ed25519_signature(&verifier_pk, &digest, &verification.verifier_signature).map_err(
        |reason| TrustError::ChallengeVerificationSignatureInvalid {
            verification_id: id_hex.clone(),
            reason,
        },
    )?;

    let expected_id = challenge_verification_id(
        &verification.verifier,
        &verification.subject,
        &verification.capability_uri,
        verification.timestamp,
    )?;
    if verification.verification_id != expected_id {
        return Err(TrustError::ChallengeVerificationIdMismatch {
            verification_id: id_hex,
            expected: hex::encode(expected_id),
        });
    }

    let validity_secs = verification
        .expires_at
        .saturating_sub(verification.timestamp);
    if validity_secs > DEFAULT_VERIFICATION_TTL_SECS {
        return Err(TrustError::ChallengeVerificationValidityTooLong {
            verification_id: id_hex,
            validity_secs,
            max_secs: DEFAULT_VERIFICATION_TTL_SECS,
        });
    }

    if verification.subject != expected_subject {
        return Err(TrustError::ChallengeSubjectMismatch {
            verification_id: id_hex,
            record_subject: verification.subject.to_string(),
            expected_subject: expected_subject.to_owned(),
        });
    }

    if verification.context_id.as_deref() != Some(target_context_id) {
        return Err(TrustError::ChallengeContextMismatch {
            verification_id: id_hex,
            record_context: verification.context_id.clone(),
            expected_context: target_context_id.to_owned(),
        });
    }

    let now = clock.now_secs();
    if verification.expires_at <= now {
        return Err(TrustError::ChallengeVerificationExpired {
            verification_id: id_hex,
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

    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    use super::*;
    use scp_clock::TestClock;

    /// A named edit to a suite, for tests that alter one field at a time.
    type CaseMutation = (&'static str, fn(&mut Vec<TestCase>));
    /// A named edit to a signed record, for tests that alter one field at a time.
    type RecordMutation = (&'static str, fn(&mut ChallengeVerification));

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// A protocol URI whose standard requires 20 cases in total.
    const TEST_CAPABILITY_URI: &str = "scp:capability:schema-validation/v1";
    const MULTILINGUAL_URI: &str = "scp:capability:multilingual/v1";
    /// Spec 25 Vector 57's identifier in the `03-identity.md` §3.1 text form.
    const TEST_DEFINER: &str = "scp:fqhx6rdyx2knwadygeppkg5dzsmtinrlb4ku3s7zywlvolsgz4za";
    const VERIFIER: &str = "did:dht:verifier";
    const SUBJECT: &str = "did:dht:subject";
    const OTHER: &str = "did:dht:other";
    const CONTEXT: &str = "ctx-1";
    const NOW: u64 = 1_700_000_000;
    const TWO_POW_53: u64 = 1 << 53;

    /// A test resolver that maps DIDs to public key bytes.
    struct TestResolver {
        keys: HashMap<String, Vec<u8>>,
    }

    impl DidPublicKeyResolver for TestResolver {
        fn resolve_public_key(&self, did: &str) -> Result<Vec<u8>, TrustError> {
            self.keys
                .get(did)
                .cloned()
                .ok_or_else(|| TrustError::KeyResolutionUnavailable {
                    did: did.to_owned(),
                    reason: "not in test resolver".to_owned(),
                })
        }
    }

    /// A test signer backed by an Ed25519 signing key; signs the digest.
    struct TestSigner(SigningKey);

    impl ChallengeSigner for TestSigner {
        fn sign(&self, digest: &[u8; 32]) -> Result<Ed25519Signature, TrustError> {
            Ok(self.0.sign(digest).to_bytes().to_vec())
        }
    }

    struct Fixture {
        verifier: TestSigner,
        subject: SigningKey,
        other: SigningKey,
        resolver: TestResolver,
        clock: TestClock,
    }

    fn fixture() -> Fixture {
        let mut rng = rand::rngs::OsRng;
        let verifier = SigningKey::generate(&mut rng);
        let subject = SigningKey::generate(&mut rng);
        let other = SigningKey::generate(&mut rng);
        let keys = HashMap::from([
            (
                VERIFIER.to_owned(),
                verifier.verifying_key().to_bytes().to_vec(),
            ),
            (
                SUBJECT.to_owned(),
                subject.verifying_key().to_bytes().to_vec(),
            ),
            (OTHER.to_owned(), other.verifying_key().to_bytes().to_vec()),
        ]);
        Fixture {
            verifier: TestSigner(verifier),
            subject,
            other,
            resolver: TestResolver { keys },
            clock: TestClock::new(NOW),
        }
    }

    fn case(test_id: &str, category: &str, weight: u32) -> TestCase {
        TestCase {
            test_id: test_id.to_owned(),
            input: json!({"prompt": test_id}),
            expected: ExpectedOutput::ExactMatch { value: json!("ok") },
            category: category.to_owned(),
            weight,
        }
    }

    /// `n` cases per `(category, n)` pair, weights summing to 10000.
    fn cases_in(categories: &[(&str, usize)]) -> Vec<TestCase> {
        let total: usize = categories.iter().map(|(_, n)| n).sum();
        let each = u32::try_from(10_000 / total).unwrap();
        let mut out = Vec::with_capacity(total);
        for (category, n) in categories {
            for i in 0..*n {
                out.push(case(&format!("{category}-{i}"), category, each));
            }
        }
        let rest = 10_000 - each * u32::try_from(total).unwrap();
        out.last_mut().unwrap().weight += rest;
        out
    }

    fn cases(n: usize) -> Vec<TestCase> {
        cases_in(&[("general", n)])
    }

    fn unsigned(
        uri: &str,
        test_cases: Vec<TestCase>,
    ) -> Result<UnsignedChallengeRequest, TrustError> {
        challenge_request_unsigned(
            VERIFIER.into(),
            SUBJECT.into(),
            uri.to_owned(),
            test_cases,
            300,
        )
    }

    fn issue(f: &Fixture) -> ChallengeRequest {
        issue_challenge(
            VERIFIER.into(),
            SUBJECT.into(),
            TEST_CAPABILITY_URI.to_owned(),
            cases(20),
            300,
            &f.verifier,
        )
        .unwrap()
    }

    fn good_result() -> serde_json::Value {
        json!({"test_count": 20, "pass_count": 19, "passed": true, "score": 9500})
    }

    /// A response signed by `key` claiming to come from `responder`.
    fn respond_as(
        key: &SigningKey,
        responder: &str,
        challenge_id: String,
        result: serde_json::Value,
        completed_at: u64,
    ) -> ChallengeResponse {
        let mut response = ChallengeResponse {
            challenge_id,
            responder_did: responder.into(),
            result,
            completed_at,
            signature: vec![],
        };
        let bytes = canonical_challenge_response_bytes(&response).unwrap();
        response.signature = key.sign(&bytes).to_bytes().to_vec();
        response
    }

    fn respond(
        f: &Fixture,
        request: &ChallengeRequest,
        result: serde_json::Value,
    ) -> ChallengeResponse {
        respond_as(
            &f.subject,
            SUBJECT,
            hex::encode(request.challenge_id),
            result,
            NOW,
        )
    }

    fn check(
        f: &Fixture,
        request: &ChallengeRequest,
        response: &ChallengeResponse,
    ) -> Result<UnsignedChallengeVerification, TrustError> {
        check_challenge_response(
            request,
            response,
            &f.resolver,
            &f.clock,
            &VERIFIER.into(),
            CONTEXT.to_owned(),
        )
    }

    /// A verifier-signed record from the happy path.
    fn signed_record(f: &Fixture) -> ChallengeVerification {
        let request = issue(f);
        let response = respond(f, &request, good_result());
        verify_challenge_response(
            &request,
            &response,
            &f.resolver,
            &f.clock,
            &f.verifier,
            &VERIFIER.into(),
            CONTEXT.to_owned(),
        )
        .unwrap()
    }

    /// Re-signs `record` over its current digest, as a verifier would.
    fn resign(f: &Fixture, mut record: ChallengeVerification) -> ChallengeVerification {
        let digest = challenge_verification_signing_digest(&record).unwrap();
        record.verifier_signature = f.verifier.sign(&digest).unwrap();
        record
    }

    fn verify(f: &Fixture, record: &ChallengeVerification) -> Result<(), TrustError> {
        verify_challenge_verification(record, &f.resolver, CONTEXT, SUBJECT, &f.clock)
    }

    /// Re-signs `request` over its current digest.
    fn resign_request(f: &Fixture, mut request: ChallengeRequest) -> ChallengeRequest {
        let digest = challenge_request_signing_digest(&request).unwrap();
        request.verifier_signature = f.verifier.sign(&digest).unwrap();
        request
    }

    // -----------------------------------------------------------------------
    // challenge_request_unsigned: suite rules (spec 07 §7.3.4)
    // -----------------------------------------------------------------------

    #[test]
    fn unsigned_rejects_weights_not_summing_to_10000() {
        let mut test_cases = cases(20);
        test_cases[0].weight += 1;
        let err = unsigned(TEST_CAPABILITY_URI, test_cases).unwrap_err();
        assert!(
            matches!(&err, TrustError::InvalidChallengeSuite { reason } if reason.contains("10001")),
            "{err:?}"
        );
    }

    #[test]
    fn unsigned_rejects_duplicate_test_id() {
        let mut test_cases = cases(20);
        test_cases[1].test_id = test_cases[0].test_id.clone();
        let err = unsigned(TEST_CAPABILITY_URI, test_cases).unwrap_err();
        assert!(
            matches!(&err, TrustError::InvalidChallengeSuite { reason } if reason.contains("repeats")),
            "{err:?}"
        );
    }

    #[test]
    fn unsigned_rejects_empty_suite() {
        let uri = format!("{TEST_DEFINER}:capability:custom/v1");
        let err = unsigned(&uri, Vec::new()).unwrap_err();
        assert!(
            matches!(&err, TrustError::InvalidChallengeSuite { reason } if reason.contains("empty")),
            "{err:?}"
        );
    }

    #[test]
    fn unsigned_rejects_system_capability() {
        for uri in [
            "scp:system:mls-group-management",
            "scp:system:key-rotation",
            "scp:system:governance-participation",
            "scp:system:relay-operation",
        ] {
            let err = unsigned(uri, cases(20)).unwrap_err();
            assert!(
                matches!(err, TrustError::NotChallengeable { .. }),
                "{uri}: {err:?}"
            );
        }
    }

    #[test]
    fn unsigned_rejects_unknown_protocol_capability() {
        for uri in [
            "scp:capability:nonexistent/v1",
            "scp:capability:outlet-integrity/v1",
            "not a uri",
            "scp:capability:schema-validation/v01",
        ] {
            let err = unsigned(uri, cases(20)).unwrap_err();
            assert!(
                matches!(err, TrustError::UnknownChallengeCapability { .. }),
                "{uri}: {err:?}"
            );
        }
    }

    #[test]
    fn unsigned_rejects_protocol_uri_below_minimum() {
        let err = unsigned(TEST_CAPABILITY_URI, cases(19)).unwrap_err();
        assert!(
            matches!(
                &err,
                TrustError::ChallengeSuiteBelowMinimum { uri, minimum: 20, supplied: 19, category: None }
                if uri == TEST_CAPABILITY_URI
            ),
            "{err:?}"
        );
    }

    #[test]
    fn unsigned_accepts_protocol_uri_at_minimum() {
        unsigned(TEST_CAPABILITY_URI, cases(20)).unwrap();
    }

    #[test]
    fn unsigned_identifier_scoped_uri_has_no_protocol_minimum() {
        let uri = format!("{TEST_DEFINER}:capability:schema-validation/v1");
        unsigned(&uri, cases(1)).unwrap();
    }

    #[test]
    fn multilingual_requires_five_per_category() {
        let err = unsigned(MULTILINGUAL_URI, cases_in(&[("en-US", 5), ("fr", 4)])).unwrap_err();
        assert!(
            matches!(
                &err,
                TrustError::ChallengeSuiteBelowMinimum { uri, minimum: 5, supplied: 4, category: Some(c) }
                if uri == MULTILINGUAL_URI && c == "fr"
            ),
            "{err:?}"
        );
    }

    #[test]
    fn multilingual_accepts_five_per_category() {
        unsigned(MULTILINGUAL_URI, cases_in(&[("en-US", 5), ("fr", 5)])).unwrap();
    }

    #[test]
    fn multilingual_counts_tags_differing_in_case_as_one_category() {
        unsigned(MULTILINGUAL_URI, cases_in(&[("en-US", 3), ("EN-us", 2)])).unwrap();
    }

    #[test]
    fn multilingual_rejects_malformed_language_tag() {
        let err = unsigned(MULTILINGUAL_URI, cases_in(&[("en_US", 5), ("fr", 5)])).unwrap_err();
        assert!(
            matches!(&err, TrustError::InvalidChallengeSuite { reason } if reason.contains("en_US")),
            "{err:?}"
        );
    }

    #[test]
    fn suite_rejects_integer_beyond_2_53() {
        let mut in_input = cases(20);
        in_input[3].input = json!({"n": [TWO_POW_53 + 1]});
        let mut in_expected = cases(20);
        in_expected[3].expected = ExpectedOutput::ExactMatch {
            value: json!({"n": TWO_POW_53 + 1}),
        };
        let mut negative = cases(20);
        negative[3].input = json!(-(i64::try_from(TWO_POW_53).unwrap() + 1));
        for (label, test_cases) in [
            ("input", in_input),
            ("expected", in_expected),
            ("negative", negative),
        ] {
            let err = unsigned(TEST_CAPABILITY_URI, test_cases).unwrap_err();
            assert!(
                matches!(&err, TrustError::InvalidChallengeSuite { reason } if reason.contains("I-JSON")),
                "{label}: {err:?}"
            );
        }
    }

    #[test]
    fn suite_accepts_integer_at_2_53() {
        let mut test_cases = cases(20);
        test_cases[3].input = json!({"n": [TWO_POW_53]});
        test_cases[4].expected = ExpectedOutput::ExactMatch {
            value: json!(-(i64::try_from(TWO_POW_53).unwrap())),
        };
        unsigned(TEST_CAPABILITY_URI, test_cases).unwrap();
    }

    #[test]
    fn unsigned_challenge_ids_are_random() {
        let a = unsigned(TEST_CAPABILITY_URI, cases(20)).unwrap();
        let b = unsigned(TEST_CAPABILITY_URI, cases(20)).unwrap();
        assert_ne!(a.challenge_id(), b.challenge_id());
        assert_ne!(a.challenge_id(), [0u8; 32]);
    }

    #[test]
    fn unsigned_digest_is_the_signed_request_digest() {
        let f = fixture();
        let unsigned = unsigned(TEST_CAPABILITY_URI, cases(20)).unwrap();
        let digest = unsigned.signing_digest();
        let request = unsigned.with_verifier_signature(f.verifier.sign(&digest).unwrap());
        assert_eq!(challenge_request_signing_digest(&request).unwrap(), digest);
    }

    #[test]
    fn challenge_request_json_challenge_id_is_lowercase_hex() {
        let f = fixture();
        let request = issue(&f);
        let json = serde_json::to_value(&request).unwrap();
        let id = json["challenge_id"].as_str().unwrap();
        assert_eq!(id, hex::encode(request.challenge_id));
        assert_eq!(id.len(), 64);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        let back: ChallengeRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, request);
    }

    // -----------------------------------------------------------------------
    // suite_digest and the request preimage (spec 07 §7.3.4, Vector 58)
    // -----------------------------------------------------------------------

    fn vector_58_case() -> TestCase {
        TestCase {
            test_id: "schema-validation-001".to_owned(),
            input: json!({"name": "widget", "count": 3}),
            expected: ExpectedOutput::SchemaMatch {
                schema: json!({"type": "object", "required": ["name", "count"]}),
            },
            category: "schema".to_owned(),
            weight: 10_000,
        }
    }

    #[test]
    fn suite_digest_matches_vector_58() {
        assert_eq!(
            hex::encode(challenge_suite_digest(&[vector_58_case()]).unwrap()),
            "728fca93ec869b96f4f784cb46ad1b2aa68a4a39d7c4b60b66707586914fdcfc"
        );
    }

    #[test]
    fn suite_digest_changes_with_each_test_case_field() {
        let base = vec![vector_58_case(), case("second", "other", 0)];
        let digest = challenge_suite_digest(&base).unwrap();
        let mutations: [CaseMutation; 6] = [
            ("test_id", |c| c[0].test_id.push('x')),
            ("input", |c| {
                c[0].input = json!({"name": "widget", "count": 4});
            }),
            ("expected", |c| {
                c[0].expected = ExpectedOutput::SchemaMatch {
                    schema: json!({"type": "array"}),
                };
            }),
            ("category", |c| c[0].category.push('x')),
            ("weight", |c| {
                c[0].weight -= 1;
                c[1].weight += 1;
            }),
            ("order", |c| c.swap(0, 1)),
        ];
        for (label, mutate) in mutations {
            let mut changed = base.clone();
            mutate(&mut changed);
            assert_ne!(challenge_suite_digest(&changed).unwrap(), digest, "{label}");
        }
    }

    #[test]
    fn suite_digest_equal_for_equal_cases_with_reordered_json_keys() {
        let a = vector_58_case();
        let mut b = vector_58_case();
        b.input = serde_json::from_str(r#"{"count": 3, "name": "widget"}"#).unwrap();
        b.expected = ExpectedOutput::SchemaMatch {
            schema: serde_json::from_str(r#"{"required": ["name", "count"], "type": "object"}"#)
                .unwrap(),
        };
        assert_eq!(
            challenge_suite_digest(&[a]).unwrap(),
            challenge_suite_digest(&[b]).unwrap()
        );
    }

    #[test]
    fn request_preimage_embeds_suite_digest_input() {
        let f = fixture();
        let request = issue(&f);
        let t = test_cases_field_bytes(&request.test_cases).unwrap();
        let r = canonical_challenge_request_bytes(&request).unwrap();
        // R = domain ‖ challenge_id ‖ F(uri) ‖ T ‖ timeout ‖ F(verifier) ‖ F(subject)
        let start = DOMAIN_CHALLENGE_REQ_V1.len() + 32 + 4 + request.capability_uri.len();
        assert_eq!(&r[start..start + t.len()], &t[..]);
        assert_eq!(
            &r[start + t.len()..start + t.len() + 4],
            &300u32.to_be_bytes()
        );
    }

    #[test]
    fn expected_output_custom_eval_round_trips_outlet_id() {
        let expected = ExpectedOutput::CustomEval {
            evaluator_outlet_id: "outlet-7".to_owned(),
        };
        let json = serde_json::to_value(&expected).unwrap();
        assert_eq!(
            json,
            json!({"CustomEval": {"evaluator_outlet_id": "outlet-7"}})
        );
        assert_eq!(
            serde_json::from_value::<ExpectedOutput>(json).unwrap(),
            expected
        );
    }

    // -----------------------------------------------------------------------
    // check_challenge_response
    // -----------------------------------------------------------------------

    #[test]
    fn check_produces_record_that_verifies() {
        let f = fixture();
        let request = issue(&f);
        let response = respond(&f, &request, good_result());
        let unsigned = check(&f, &request, &response).unwrap();
        let record = unsigned.record();
        assert_eq!(record.timestamp, NOW);
        assert_eq!(record.expires_at, NOW + DEFAULT_VERIFICATION_TTL_SECS);
        assert_eq!(record.context_id.as_deref(), Some(CONTEXT));
        assert_eq!(
            record.verification_id,
            challenge_verification_id(&VERIFIER.into(), &SUBJECT.into(), TEST_CAPABILITY_URI, NOW)
                .unwrap()
        );
        assert_eq!((record.test_count, record.pass_count), (20, 19));
        assert_eq!(record.score, Some(9500));
        assert!(record.passed);
        assert_eq!(
            record.verification_method,
            VerificationMethod::ChallengeVerified {
                challenge_type: ChallengeType::schema_validation()
            }
        );
        let digest = unsigned.signing_digest();
        let signed = unsigned.with_verifier_signature(f.verifier.sign(&digest).unwrap());
        verify(&f, &signed).unwrap();
    }

    #[test]
    fn check_response_record_carries_request_suite_digest() {
        let f = fixture();
        let request = issue(&f);
        let response = respond(&f, &request, good_result());
        let record = check(&f, &request, &response).unwrap();
        assert_eq!(
            record.record().suite_digest,
            challenge_suite_digest(&request.test_cases).unwrap()
        );
    }

    #[test]
    fn check_rejects_verifier_not_matching_request() {
        let f = fixture();
        let request = issue(&f);
        let response = respond(&f, &request, good_result());
        let err = check_challenge_response(
            &request,
            &response,
            &f.resolver,
            &f.clock,
            &OTHER.into(),
            CONTEXT.to_owned(),
        )
        .unwrap_err();
        assert!(
            matches!(err, TrustError::ChallengeVerifierMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn check_rejects_mismatched_challenge_id() {
        let f = fixture();
        let request = issue(&f);
        let response = respond_as(&f.subject, SUBJECT, "00".repeat(32), good_result(), NOW);
        let err = check(&f, &request, &response).unwrap_err();
        assert!(
            matches!(err, TrustError::ChallengeIdMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn check_rejects_uppercase_response_challenge_id() {
        let f = fixture();
        let request = issue(&f);
        let upper = hex::encode_upper(request.challenge_id);
        assert_ne!(upper, hex::encode(request.challenge_id));
        let response = respond_as(&f.subject, SUBJECT, upper, good_result(), NOW);
        let err = check(&f, &request, &response).unwrap_err();
        assert!(
            matches!(err, TrustError::ChallengeIdMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn check_rejects_wrong_responder() {
        let f = fixture();
        let request = issue(&f);
        let response = respond_as(
            &f.other,
            OTHER,
            hex::encode(request.challenge_id),
            good_result(),
            NOW,
        );
        let err = check(&f, &request, &response).unwrap_err();
        assert!(
            matches!(err, TrustError::ChallengeResponderMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn verify_rejects_request_signed_over_raw_canonical_bytes() {
        let f = fixture();
        let mut request = issue(&f);
        let raw = canonical_challenge_request_bytes(&request).unwrap();
        request.verifier_signature = f.verifier.0.sign(&raw).to_bytes().to_vec();
        let response = respond(&f, &request, good_result());
        let err = check(&f, &request, &response).unwrap_err();
        assert!(
            matches!(err, TrustError::ChallengeRequestSignatureInvalid { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn check_rejects_request_with_subject_swapped_after_signing() {
        let f = fixture();
        let mut request = issue(&f);
        request.subject = OTHER.into();
        // The swapped-in subject answers, so only the request signature fails.
        let response = respond_as(
            &f.other,
            OTHER,
            hex::encode(request.challenge_id),
            good_result(),
            NOW,
        );
        let err = check(&f, &request, &response).unwrap_err();
        assert!(
            matches!(err, TrustError::ChallengeRequestSignatureInvalid { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn check_rejects_request_with_test_case_altered_after_signing() {
        let f = fixture();
        let mut request = issue(&f);
        request.test_cases[7].input = json!({"prompt": "altered"});
        let response = respond(&f, &request, good_result());
        let err = check(&f, &request, &response).unwrap_err();
        assert!(
            matches!(err, TrustError::ChallengeRequestSignatureInvalid { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn check_accepts_request_resigned_after_alteration() {
        // Control for the two tests above: the same alteration, re-signed,
        // passes, so they fail on the signature and nothing else.
        let f = fixture();
        let mut request = issue(&f);
        request.test_cases[7].input = json!({"prompt": "altered"});
        let request = resign_request(&f, request);
        let response = respond(&f, &request, good_result());
        check(&f, &request, &response).unwrap();
    }

    #[test]
    fn check_rejects_response_older_than_timeout() {
        let f = fixture();
        let request = issue(&f);
        let id = hex::encode(request.challenge_id);
        let stale = respond_as(&f.subject, SUBJECT, id.clone(), good_result(), NOW - 301);
        let err = check(&f, &request, &stale).unwrap_err();
        assert!(
            matches!(err, TrustError::ChallengeTimeout { .. }),
            "{err:?}"
        );
        let edge = respond_as(&f.subject, SUBJECT, id, good_result(), NOW - 300);
        check(&f, &request, &edge).unwrap();
    }

    #[test]
    fn check_rejects_far_future_completed_at() {
        let f = fixture();
        let request = issue(&f);
        let id = hex::encode(request.challenge_id);
        let future = respond_as(&f.subject, SUBJECT, id.clone(), good_result(), NOW + 301);
        let err = check(&f, &request, &future).unwrap_err();
        assert!(
            matches!(err, TrustError::ChallengeTimeout { .. }),
            "{err:?}"
        );
        let edge = respond_as(&f.subject, SUBJECT, id, good_result(), NOW + 300);
        check(&f, &request, &edge).unwrap();
    }

    #[test]
    fn check_rejects_invalid_response_signature() {
        let f = fixture();
        let request = issue(&f);
        let mut response = respond(&f, &request, good_result());
        response.result = json!({"test_count": 20, "pass_count": 20, "passed": true});
        let err = check(&f, &request, &response).unwrap_err();
        assert!(
            matches!(err, TrustError::ChallengeSignatureInvalid { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn check_propagates_resolver_failure() {
        let mut f = fixture();
        f.resolver.keys.remove(VERIFIER);
        let request = issue(&f);
        let response = respond(&f, &request, good_result());
        let err = check(&f, &request, &response).unwrap_err();
        assert!(
            matches!(err, TrustError::KeyResolutionUnavailable { .. }),
            "{err:?}"
        );
    }

    fn check_result(
        result: serde_json::Value,
    ) -> Result<UnsignedChallengeVerification, TrustError> {
        let f = fixture();
        let request = issue(&f);
        let response = respond(&f, &request, result);
        check(&f, &request, &response)
    }

    fn assert_invalid_response(result: &serde_json::Value, needle: &str) {
        let err = check_result(result.clone()).unwrap_err();
        assert!(
            matches!(&err, TrustError::InvalidChallengeResponse { reason, .. } if reason.contains(needle)),
            "{result}: {err:?}"
        );
    }

    #[test]
    fn check_rejects_score_above_10000() {
        assert_invalid_response(
            &json!({"test_count": 20, "pass_count": 20, "passed": true, "score": 10_001}),
            "score",
        );
        let at_max = check_result(
            json!({"test_count": 20, "pass_count": 20, "passed": true, "score": 10_000}),
        );
        assert_eq!(at_max.unwrap().record().score, Some(10_000));
    }

    #[test]
    fn check_rejects_test_count_not_matching_request() {
        assert_invalid_response(
            &json!({"test_count": 19, "pass_count": 19, "passed": true}),
            "test_count 19",
        );
        assert_invalid_response(
            &json!({"test_count": 21, "pass_count": 19, "passed": true}),
            "test_count 21",
        );
    }

    #[test]
    fn check_rejects_pass_count_above_test_count() {
        assert_invalid_response(
            &json!({"test_count": 20, "pass_count": 21, "passed": true}),
            "pass_count 21",
        );
    }

    #[test]
    fn check_rejects_missing_or_mistyped_counts() {
        for (result, needle) in [
            (json!({"pass_count": 20, "passed": true}), "test_count"),
            (json!({"test_count": 20, "passed": true}), "pass_count"),
            (json!({"test_count": 20, "pass_count": 20}), "passed"),
            (
                json!({"test_count": "20", "pass_count": 20, "passed": true}),
                "test_count",
            ),
            (
                json!({"test_count": 20, "pass_count": 20, "passed": "yes"}),
                "passed",
            ),
            (
                json!({"test_count": 4_294_967_316_u64, "pass_count": 20, "passed": true}),
                "test_count",
            ),
            (
                json!({"test_count": 20, "pass_count": -1, "passed": true}),
                "pass_count",
            ),
            (
                json!({"test_count": 20, "pass_count": 20, "passed": true, "score": 1.5}),
                "score",
            ),
            (json!([20, 20, true]), "test_count"),
        ] {
            assert_invalid_response(&result, needle);
        }
    }

    #[test]
    fn check_reads_absent_or_null_score_as_none() {
        for result in [
            json!({"test_count": 20, "pass_count": 0, "passed": false}),
            json!({"test_count": 20, "pass_count": 0, "passed": false, "score": null}),
        ] {
            assert_eq!(check_result(result).unwrap().record().score, None);
        }
    }

    #[test]
    fn response_result_rejects_integer_beyond_2_53() {
        let f = fixture();
        let request = issue(&f);
        let response = ChallengeResponse {
            challenge_id: hex::encode(request.challenge_id),
            responder_did: SUBJECT.into(),
            result: json!({"test_count": 20, "pass_count": 20, "passed": true, "n": TWO_POW_53 + 1}),
            completed_at: NOW,
            signature: vec![0; 64],
        };
        let err = canonical_challenge_response_bytes(&response).unwrap_err();
        assert!(
            matches!(err, TrustError::InvalidChallengeResponse { .. }),
            "{err:?}"
        );
        let err = check(&f, &request, &response).unwrap_err();
        assert!(
            matches!(err, TrustError::InvalidChallengeResponse { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn response_result_accepts_integer_at_2_53() {
        let f = fixture();
        let request = issue(&f);
        let result = json!({"test_count": 20, "pass_count": 20, "passed": true, "n": TWO_POW_53});
        let response = respond(&f, &request, result);
        check(&f, &request, &response).unwrap();
    }

    // -----------------------------------------------------------------------
    // verify_challenge_verification
    // -----------------------------------------------------------------------

    #[test]
    fn verify_accepts_happy_path_record() {
        let f = fixture();
        verify(&f, &signed_record(&f)).unwrap();
    }

    #[test]
    fn verify_challenge_verification_rejects_raw_signed_record() {
        let f = fixture();
        let mut record = signed_record(&f);
        let raw = canonical_challenge_verification_bytes(&record).unwrap();
        record.verifier_signature = f.verifier.0.sign(&raw).to_bytes().to_vec();
        let err = verify(&f, &record).unwrap_err();
        assert!(
            matches!(
                err,
                TrustError::ChallengeVerificationSignatureInvalid { .. }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn verify_rejects_record_with_suite_digest_altered_after_signing() {
        let f = fixture();
        let mut record = signed_record(&f);
        record.suite_digest[0] ^= 1;
        let err = verify(&f, &record).unwrap_err();
        assert!(
            matches!(
                err,
                TrustError::ChallengeVerificationSignatureInvalid { .. }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn verify_rejects_each_signed_field_altered_after_signing() {
        let f = fixture();
        let base = signed_record(&f);
        let mutations: [RecordMutation; 8] = [
            ("passed", |r| r.passed = !r.passed),
            ("score", |r| r.score = None),
            ("test_count", |r| r.test_count += 1),
            ("pass_count", |r| r.pass_count += 1),
            ("expires_at", |r| r.expires_at -= 1),
            ("context_id", |r| r.context_id = Some("ctx-2".to_owned())),
            ("verification_id", |r| r.verification_id[0] ^= 1),
            ("capability_uri", |r| {
                r.capability_uri = "scp:capability:bias-resistance/v1".to_owned();
            }),
        ];
        for (label, mutate) in mutations {
            let mut record = base.clone();
            mutate(&mut record);
            let err = verify(&f, &record).unwrap_err();
            assert!(
                matches!(
                    err,
                    TrustError::ChallengeVerificationSignatureInvalid { .. }
                ),
                "{label}: {err:?}"
            );
        }
    }

    #[test]
    fn verify_ignores_unsigned_fields() {
        let f = fixture();
        let mut record = signed_record(&f);
        record.result = json!({"anything": true});
        record.completed_at = 0;
        record.verification_method = VerificationMethod::SelfAttested;
        verify(&f, &record).unwrap();
    }

    #[test]
    fn verify_rejects_verification_id_not_derived() {
        let f = fixture();
        let mut record = signed_record(&f);
        record.verification_id = [7; 32];
        let err = verify(&f, &resign(&f, record)).unwrap_err();
        assert!(
            matches!(err, TrustError::ChallengeVerificationIdMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn verify_rejects_expiry_beyond_90_days() {
        let f = fixture();
        let mut record = signed_record(&f);
        record.expires_at = record.timestamp + DEFAULT_VERIFICATION_TTL_SECS + 1;
        let err = verify(&f, &resign(&f, record)).unwrap_err();
        let expected_id = hex::encode(signed_record(&f).verification_id);
        assert!(
            matches!(
                &err,
                TrustError::ChallengeVerificationValidityTooLong { verification_id, validity_secs, max_secs }
                if *verification_id == expected_id
                    && *validity_secs == DEFAULT_VERIFICATION_TTL_SECS + 1
                    && *max_secs == DEFAULT_VERIFICATION_TTL_SECS
            ),
            "{err:?}"
        );
    }

    #[test]
    fn verify_rejects_mismatched_subject() {
        let f = fixture();
        let record = signed_record(&f);
        let err = verify_challenge_verification(&record, &f.resolver, CONTEXT, OTHER, &f.clock)
            .unwrap_err();
        assert!(
            matches!(err, TrustError::ChallengeSubjectMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn verify_rejects_other_or_absent_context() {
        let f = fixture();
        let record = signed_record(&f);
        let err = verify_challenge_verification(&record, &f.resolver, "ctx-2", SUBJECT, &f.clock)
            .unwrap_err();
        assert!(
            matches!(err, TrustError::ChallengeContextMismatch { .. }),
            "{err:?}"
        );
        let mut absent = record;
        absent.context_id = None;
        let err = verify(&f, &resign(&f, absent)).unwrap_err();
        assert!(
            matches!(err, TrustError::ChallengeContextMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn verify_rejects_expired_record() {
        let f = fixture();
        let record = signed_record(&f);
        f.clock.set(record.expires_at);
        let err = verify(&f, &record).unwrap_err();
        assert!(
            matches!(err, TrustError::ChallengeVerificationExpired { .. }),
            "{err:?}"
        );
        f.clock.set(record.expires_at - 1);
        verify(&f, &record).unwrap();
    }

    #[test]
    fn verification_json_ids_are_lowercase_hex() {
        let f = fixture();
        let record = signed_record(&f);
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["verification_id"], hex::encode(record.verification_id));
        assert_eq!(json["suite_digest"], hex::encode(record.suite_digest));
        assert_eq!(
            serde_json::from_value::<ChallengeVerification>(json).unwrap(),
            record
        );
    }

    // -----------------------------------------------------------------------
    // ChallengeType
    // -----------------------------------------------------------------------

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
            pir.uri().to_string(),
            "scp:capability:prompt-injection-resistance/v1"
        );
        assert_eq!(sv.uri().to_string(), "scp:capability:schema-validation/v1");
        assert_eq!(
            rlc.uri().to_string(),
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
    fn deserialize_identifier_scoped_uri() {
        let uri = format!("{TEST_DEFINER}:capability:custom-check/v1");
        let ct: ChallengeType = serde_json::from_value(serde_json::json!(uri)).unwrap();
        assert_eq!(ct, ChallengeType::Uri(uri.parse().unwrap()));
    }

    #[test]
    fn challenge_type_rejects_did_scoped_uri() {
        let result: Result<ChallengeType, _> =
            serde_json::from_str("\"did:dht:z6Mk123:capability:custom-check/v1\"");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not a canonical identifier"),
            "expected the NonCanonicalIdentifier text, got {err}"
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
            ChallengeType::Uri(
                format!("{TEST_DEFINER}:capability:custom/v1")
                    .parse()
                    .unwrap(),
            ),
        ];
        for ct in &types {
            let json = serde_json::to_string(ct).unwrap();
            let deserialized: ChallengeType = serde_json::from_str(&json).unwrap();
            assert_eq!(ct, &deserialized, "roundtrip failed for {json}");
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

    // -----------------------------------------------------------------------
    // Backwards-compatibility deserialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn deserialize_legacy_custom_with_identifier_scoped_uri() {
        // Legacy "Custom:scp:<identifier>:capability:x/v1" should deserialize.
        let uri = format!("{TEST_DEFINER}:capability:x/v1");
        let ct: ChallengeType =
            serde_json::from_value(serde_json::json!(format!("Custom:{uri}"))).unwrap();
        assert_eq!(ct, ChallengeType::Uri(uri.parse().unwrap()));
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
}
