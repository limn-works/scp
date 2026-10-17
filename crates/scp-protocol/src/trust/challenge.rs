//! Challenge-response protocol for trust verification (spec 07 §7.3.4).
//!
//! A challenger tests a subject's claimed capability with test cases it
//! writes. The subject sees each case's input, never its expected output,
//! and nothing derived from it. The challenger grades the outputs against
//! the expected outputs it kept and signs a record of the result for every
//! graded attempt.
//!
//! # Flow
//!
//! 1. **Issue.** [`ChallengePolicy::resolve`] obtains the capability
//!    definition (§7.3.4.6) and fixes the signed policy within its limits.
//!    [`challenge_request_unsigned`] checks the suite and returns the request
//!    to sign plus the [`AnswerKey`] the challenger keeps.
//! 2. **Respond.** The subject checks the request with
//!    [`challenge_response_unsigned`] and signs one output per case.
//! 3. **Grade.** The challenger bounds the raw response with
//!    [`check_response_bounds`], authenticates it with
//!    [`authenticate_challenge_response`], checks the attempt against its
//!    ledger with [`check_attempt`], and computes a [`GradeOutcome`] with
//!    [`grade`].
//! 4. **Record.** [`challenge_verification_unsigned`] builds the record the
//!    challenger signs.
//! 5. **Consume.** A party checks a record with
//!    [`verify_challenge_verification`].
//!
//! Signatures cover the 32-byte SHA-256 digest of each canonical preimage,
//! never the preimage itself. Signatures are Ed25519 until the P-256 move;
//! spec 07 types them `P256Signature`.
//!
//! See ADR-017 in `.docs/adrs/phase-4.md` and ADR-041 for `ChallengeType`
//! unification.

use std::collections::{BTreeMap, HashSet};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use scp_clock::Clock;
use scp_crypto::verify_ed25519_signature;
use scp_did::DID;
use scp_event_log::Ed25519Signature;

use super::TrustError;
use super::attestation::ActiveKeyResolver;
use super::capability_definition::{CapabilityDefinition, CapabilityDefinitionSource};
use super::capability_registry::{MinCases, validate_capability_uri};
use super::capability_uri::CapabilityUri;
use super::identifier::CanonicalIdentifier;
use super::language_tag::is_well_formed_language_tag;
use super::schema_gate::{SchemaGate, SchemaVerdict};
use crate::crypto::canonical::{CanonicalField, canonical_hash_bytes};

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

/// One test case as the challenger writes it (spec 07 §7.3.4). It never
/// leaves the challenger: the subject sees its [`ChallengeCase`].
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
    /// Importance weight in basis points; the suite's weights sum to 10000.
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
    /// Every string in `required` appears, case-sensitively, in one of the output's string leaves or object keys.
    ContainsAll {
        /// Strings that must all appear.
        required: Vec<String>,
    },
    /// No string in `forbidden` appears, case-sensitively, in one of the output's string leaves or object keys.
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
// Wire structures (spec 07 §7.3.4)
// ---------------------------------------------------------------------------

/// One test case as the subject sees it: the case without its expected
/// output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeCase {
    /// Identifier, unique within the suite.
    pub test_id: String,
    /// JSON input given to the subject (I-JSON).
    pub input: serde_json::Value,
    /// Test category; for `multilingual/v1` a BCP 47 tag.
    pub category: String,
    /// Weight in basis points.
    pub weight: u32,
}

/// A signed challenge request. Every field except `verifier_signature` is
/// covered by the signature, over [`challenge_request_signing_digest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRequest {
    /// Random 32-byte challenge identifier, lowercase hex on the wire.
    #[serde(with = "crate::identity::scpid::hex_serde_32")]
    pub challenge_id: [u8; 32],
    /// The capability URI under test, in canonical form.
    pub capability_uri: String,
    /// Digest of the capability definition followed (§7.3.4.6).
    #[serde(with = "crate::identity::scpid::hex_serde_32")]
    pub definition_digest: [u8; 32],
    /// The cases the subject answers, in order.
    pub test_cases: Vec<ChallengeCase>,
    /// Unix seconds, challenger clock.
    pub created_at: u64,
    /// Unix seconds; the window is at most `MAX_CHALLENGE_WINDOW_SECS`.
    pub expires_at: u64,
    /// Retries after the first attempt; at most the definition's.
    pub max_retries: u32,
    /// Seconds between graded attempts; at least the definition's.
    pub cooldown_secs: u32,
    /// The definition's pass threshold, in basis points.
    pub pass_threshold_bps: u32,
    /// The context the challenge is administered in.
    pub context_id: String,
    /// The challenger, signed as its UTF-8 text.
    pub verifier: DID,
    /// The subject, signed as its UTF-8 text.
    pub subject: DID,
    /// The verifier's `#active` signature over the request digest `D`.
    pub verifier_signature: Ed25519Signature,
}

/// One output, answering the case with the same `test_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestOutput {
    /// The case answered.
    pub test_id: String,
    /// The subject's output (I-JSON).
    pub output: serde_json::Value,
}

/// A subject's signed answer to one attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// The request's challenge id, lowercase hex on the wire.
    #[serde(with = "crate::identity::scpid::hex_serde_32")]
    pub challenge_id: [u8; 32],
    /// The request digest `D` this response answers.
    #[serde(with = "crate::identity::scpid::hex_serde_32")]
    pub request_digest: [u8; 32],
    /// The subject, as named in the request.
    pub subject: DID,
    /// 1-based attempt number.
    pub attempt: u32,
    /// One output per case, in case order.
    pub outputs: Vec<TestOutput>,
    /// The subject's `#active` signature over the response digest `D_r`.
    pub subject_signature: Ed25519Signature,
}

/// A record the challenger signs for one graded attempt (spec 07 §7.3.4).
/// Every field except `verifier_signature` is signed, in `R_v` order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeVerification {
    /// [`challenge_verification_id`] of the record, lowercase hex.
    #[serde(with = "crate::identity::scpid::hex_serde_32")]
    pub verification_id: [u8; 32],
    /// The challenger.
    pub verifier: DID,
    /// The subject.
    pub subject: DID,
    /// The capability URI tested.
    pub capability_uri: String,
    /// Digest of the capability definition followed.
    #[serde(with = "crate::identity::scpid::hex_serde_32")]
    pub definition_digest: [u8; 32],
    /// [`challenge_suite_digest`] of the request's cases.
    #[serde(with = "crate::identity::scpid::hex_serde_32")]
    pub suite_digest: [u8; 32],
    /// The request's challenge id.
    #[serde(with = "crate::identity::scpid::hex_serde_32")]
    pub challenge_id: [u8; 32],
    /// The graded attempt.
    pub attempt: u32,
    /// `D_r` of the response this record graded.
    #[serde(with = "crate::identity::scpid::hex_serde_32")]
    pub response_digest: [u8; 32],
    /// The request's retry count.
    pub max_retries: u32,
    /// The request's cooldown.
    pub cooldown_secs: u32,
    /// The request's pass threshold.
    pub pass_threshold_bps: u32,
    /// The smallest per-category case count, categories ASCII case-folded.
    pub min_category_cases: u32,
    /// `score >= pass_threshold_bps`.
    pub passed: bool,
    /// Sum of the weights of passed cases, in basis points.
    pub score: u32,
    /// Number of cases.
    pub test_count: u32,
    /// Number of passed cases.
    pub pass_count: u32,
    /// The request's `created_at`.
    pub challenge_created_at: u64,
    /// The request's `expires_at`.
    pub challenge_expires_at: u64,
    /// When the challenger graded, on its clock.
    pub timestamp: u64,
    /// When the record stops counting.
    pub expires_at: u64,
    /// The request's context.
    pub context_id: String,
    /// The verifier's `#active` signature over `D_v`.
    pub verifier_signature: Ed25519Signature,
}

// ---------------------------------------------------------------------------
// Protocol constants (`09-security-model.md` §9.18.18)
// ---------------------------------------------------------------------------

/// The sum every suite's weights reach, and the largest score.
pub const TOTAL_WEIGHT_BPS: u32 = 10_000;
/// The longest challenge window `expires_at - created_at`.
pub const MAX_CHALLENGE_WINDOW_SECS: u64 = 604_800;
/// The longest record validity `expires_at - timestamp`.
pub const MAX_VERIFICATION_VALIDITY_SECS: u64 = 7_776_000;
/// Clock skew allowed between parties on challenge times.
pub const CHALLENGE_CLOCK_SKEW_SECS: u64 = 300;
/// The most trusted verifiers one requirement lists.
pub const MAX_TRUSTED_VERIFIERS_PER_REQUIREMENT: usize = 32;
/// The total evaluation time for one attempt.
pub const CHALLENGE_GRADING_BUDGET_SECS: u64 = 60;
/// Added to the budget to form a grading lease deadline.
pub const CHALLENGE_LEASE_MARGIN_SECS: u64 = 30;
/// The largest response a challenger reads.
pub const MAX_CHALLENGE_RESPONSE_BYTES: usize = 1_048_576;
/// The largest canonical `SchemaMatch` schema.
pub const MAX_CHALLENGE_SCHEMA_BYTES: usize = 65_536;
/// The deepest container nesting in a schema or a response.
pub const MAX_CHALLENGE_JSON_DEPTH: usize = 64;
/// The largest capability definition description.
pub const MAX_CAPABILITY_DESCRIPTION_BYTES: usize = 1024;
/// The most capability requirements one context holds.
pub const MAX_CAPABILITY_REQUIREMENTS_PER_CONTEXT: usize = 64;

/// Domain separator of the request preimage `R`.
const DOMAIN_CHALLENGE_REQ_V1: &[u8] = b"SCP-CHALLENGE-REQ-V1:";
/// Domain separator of the response preimage `P`.
const DOMAIN_CHALLENGE_RESP_V1: &[u8] = b"SCP-CHALLENGE-RESP-V1:";
/// Domain separator of the record preimage `R_v`.
const DOMAIN_CHALLENGE_VERIFY_V1: &[u8] = b"SCP-CHALLENGE-VERIFY-V1:";

// ---------------------------------------------------------------------------
// Canonical encodings
// ---------------------------------------------------------------------------

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn encode(domain: &[u8], fields: &[CanonicalField<'_>], what: &str) -> Result<Vec<u8>, TrustError> {
    canonical_hash_bytes(domain, fields).map_err(|e| TrustError::CanonicalizationFailed {
        reason: format!("{what} preimage failed: {e}"),
    })
}

/// RFC 8785 bytes of a JSON value after the I-JSON check; `what` names the
/// value in the error.
fn jcs(value: &impl Serialize, what: &str) -> Result<Vec<u8>, TrustError> {
    crate::jcs::to_vec(value).map_err(|e| TrustError::CanonicalizationFailed {
        reason: format!("{what}: {e}"),
    })
}

/// The field `T`: `U32(n)`, then per case `F(test_id) ‖ F(JCS(input)) ‖
/// F(category) ‖ U32(weight)`. No separator.
fn test_cases_field_bytes(cases: &[ChallengeCase]) -> Result<Vec<u8>, TrustError> {
    let count = u32::try_from(cases.len()).map_err(|_| TrustError::InvalidChallengeSuite {
        reason: format!("{} test cases exceed u32::MAX", cases.len()),
    })?;
    let inputs = cases
        .iter()
        .map(|case| jcs(&case.input, &format!("test case {:?} input", case.test_id)))
        .collect::<Result<Vec<_>, _>>()?;
    let mut fields = Vec::with_capacity(1 + 4 * cases.len());
    fields.push(CanonicalField::U32(count));
    for (case, input) in cases.iter().zip(&inputs) {
        fields.extend([
            CanonicalField::VarBytes(case.test_id.as_bytes()),
            CanonicalField::VarBytes(input),
            CanonicalField::VarBytes(case.category.as_bytes()),
            CanonicalField::U32(case.weight),
        ]);
    }
    encode(b"", &fields, "test_cases")
}

/// `suite_digest = SHA-256(T)`.
///
/// # Errors
///
/// [`TrustError::CanonicalizationFailed`] if an input breaks I-JSON.
pub fn challenge_suite_digest(cases: &[ChallengeCase]) -> Result<[u8; 32], TrustError> {
    Ok(sha256(&test_cases_field_bytes(cases)?))
}

/// The request preimage `R`, public so an auditor can re-derive it.
///
/// # Errors
///
/// [`TrustError::CanonicalizationFailed`] if an input breaks I-JSON.
pub fn canonical_challenge_request_bytes(
    request: &ChallengeRequest,
) -> Result<Vec<u8>, TrustError> {
    let t = test_cases_field_bytes(&request.test_cases)?;
    encode(
        DOMAIN_CHALLENGE_REQ_V1,
        &[
            CanonicalField::Fixed32(&request.challenge_id),
            CanonicalField::VarBytes(request.capability_uri.as_bytes()),
            CanonicalField::Fixed32(&request.definition_digest),
            CanonicalField::RawBytes(&t),
            CanonicalField::U64(request.created_at),
            CanonicalField::U64(request.expires_at),
            CanonicalField::U32(request.max_retries),
            CanonicalField::U32(request.cooldown_secs),
            CanonicalField::U32(request.pass_threshold_bps),
            CanonicalField::VarBytes(request.context_id.as_bytes()),
            CanonicalField::VarBytes(request.verifier.as_bytes()),
            CanonicalField::VarBytes(request.subject.as_bytes()),
        ],
        "challenge request",
    )
}

/// `D = SHA-256(R)`, which the verifier signs.
///
/// # Errors
///
/// As [`canonical_challenge_request_bytes`].
pub fn challenge_request_signing_digest(
    request: &ChallengeRequest,
) -> Result<[u8; 32], TrustError> {
    Ok(sha256(&canonical_challenge_request_bytes(request)?))
}

/// The response preimage `P`, public so an auditor can re-derive it.
///
/// # Errors
///
/// [`TrustError::CanonicalizationFailed`] if an output breaks I-JSON.
pub fn canonical_challenge_response_bytes(
    response: &ChallengeResponse,
) -> Result<Vec<u8>, TrustError> {
    let count =
        u32::try_from(response.outputs.len()).map_err(|_| TrustError::CanonicalizationFailed {
            reason: format!("{} outputs exceed u32::MAX", response.outputs.len()),
        })?;
    let outputs = response
        .outputs
        .iter()
        .map(|o| jcs(&o.output, &format!("output {:?}", o.test_id)))
        .collect::<Result<Vec<_>, _>>()?;
    let mut fields = vec![
        CanonicalField::Fixed32(&response.challenge_id),
        CanonicalField::Fixed32(&response.request_digest),
        CanonicalField::VarBytes(response.subject.as_bytes()),
        CanonicalField::U32(response.attempt),
        CanonicalField::U32(count),
    ];
    for (o, bytes) in response.outputs.iter().zip(&outputs) {
        fields.extend([
            CanonicalField::VarBytes(o.test_id.as_bytes()),
            CanonicalField::VarBytes(bytes),
        ]);
    }
    encode(DOMAIN_CHALLENGE_RESP_V1, &fields, "challenge response")
}

/// `D_r = SHA-256(P)`, which the subject signs.
///
/// # Errors
///
/// As [`canonical_challenge_response_bytes`].
pub fn challenge_response_signing_digest(
    response: &ChallengeResponse,
) -> Result<[u8; 32], TrustError> {
    Ok(sha256(&canonical_challenge_response_bytes(response)?))
}

/// `verification_id = SHA-256(F(verifier) ‖ F(subject) ‖ F(capability_uri) ‖
/// Fixed32(challenge_id) ‖ U32(attempt) ‖ U64(timestamp))`, no separator.
///
/// # Errors
///
/// [`TrustError::CanonicalizationFailed`] if a field exceeds `u32::MAX`
/// bytes.
pub fn challenge_verification_id(
    verifier: &str,
    subject: &str,
    capability_uri: &str,
    challenge_id: &[u8; 32],
    attempt: u32,
    timestamp: u64,
) -> Result<[u8; 32], TrustError> {
    Ok(sha256(&encode(
        b"",
        &[
            CanonicalField::VarBytes(verifier.as_bytes()),
            CanonicalField::VarBytes(subject.as_bytes()),
            CanonicalField::VarBytes(capability_uri.as_bytes()),
            CanonicalField::Fixed32(challenge_id),
            CanonicalField::U32(attempt),
            CanonicalField::U64(timestamp),
        ],
        "verification_id",
    )?))
}

/// The record preimage `R_v`: 22 fields, none optional. Public so an auditor
/// can re-derive the bytes a record's digest covers.
///
/// # Errors
///
/// [`TrustError::CanonicalizationFailed`] if a field exceeds `u32::MAX`
/// bytes.
pub fn canonical_challenge_verification_bytes(
    v: &ChallengeVerification,
) -> Result<Vec<u8>, TrustError> {
    encode(
        DOMAIN_CHALLENGE_VERIFY_V1,
        &[
            CanonicalField::Fixed32(&v.verification_id),
            CanonicalField::VarBytes(v.verifier.as_bytes()),
            CanonicalField::VarBytes(v.subject.as_bytes()),
            CanonicalField::VarBytes(v.capability_uri.as_bytes()),
            CanonicalField::Fixed32(&v.definition_digest),
            CanonicalField::Fixed32(&v.suite_digest),
            CanonicalField::Fixed32(&v.challenge_id),
            CanonicalField::U32(v.attempt),
            CanonicalField::Fixed32(&v.response_digest),
            CanonicalField::U32(v.max_retries),
            CanonicalField::U32(v.cooldown_secs),
            CanonicalField::U32(v.pass_threshold_bps),
            CanonicalField::U32(v.min_category_cases),
            CanonicalField::U8(u8::from(v.passed)),
            CanonicalField::U32(v.score),
            CanonicalField::U32(v.test_count),
            CanonicalField::U32(v.pass_count),
            CanonicalField::U64(v.challenge_created_at),
            CanonicalField::U64(v.challenge_expires_at),
            CanonicalField::U64(v.timestamp),
            CanonicalField::U64(v.expires_at),
            CanonicalField::VarBytes(v.context_id.as_bytes()),
        ],
        "challenge verification",
    )
}

/// `D_v = SHA-256(R_v)`, which the verifier signs.
///
/// # Errors
///
/// As [`canonical_challenge_verification_bytes`].
pub fn challenge_verification_signing_digest(
    v: &ChallengeVerification,
) -> Result<[u8; 32], TrustError> {
    Ok(sha256(&canonical_challenge_verification_bytes(v)?))
}

/// The smallest number of cases in any one category, categories grouped by
/// `to_ascii_lowercase()`; 0 for no cases.
#[must_use]
pub fn min_category_cases<'a>(categories: impl IntoIterator<Item = &'a str>) -> u32 {
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for category in categories {
        let n = counts.entry(category.to_ascii_lowercase()).or_insert(0);
        *n = n.saturating_add(1);
    }
    counts.into_values().min().unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Unsigned records
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

    /// The request to be signed; its `verifier_signature` is empty.
    #[must_use]
    pub const fn request(&self) -> &ChallengeRequest {
        &self.request
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

/// A checked response awaiting the subject's signature.
#[derive(Debug, Clone)]
pub struct UnsignedChallengeResponse {
    response: ChallengeResponse,
    digest: [u8; 32],
}

impl UnsignedChallengeResponse {
    /// The digest `D_r` the subject signs with its `#active` key.
    #[must_use]
    pub const fn signing_digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The response to be signed; its `subject_signature` is empty.
    #[must_use]
    pub const fn response(&self) -> &ChallengeResponse {
        &self.response
    }

    /// Attaches the subject's signature over [`signing_digest`](Self::signing_digest).
    #[must_use]
    pub fn with_subject_signature(self, signature: Ed25519Signature) -> ChallengeResponse {
        ChallengeResponse {
            subject_signature: signature,
            ..self.response
        }
    }
}

/// A checked verification record awaiting the verifier's signature.
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
// Answer key
// ---------------------------------------------------------------------------

/// The challenger's expected outputs, one per case in case order. It never
/// leaves the challenger: no byte of the request derives from it (spec 07
/// §7.3.4).
///
/// `Debug` prints only the count, so a log line cannot leak an answer.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerKey {
    expected: Vec<ExpectedOutput>,
}

impl AnswerKey {
    /// The expected outputs, in case order.
    #[must_use]
    pub fn expected(&self) -> &[ExpectedOutput] {
        &self.expected
    }
}

impl std::fmt::Debug for AnswerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnswerKey")
            .field("cases", &self.expected.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Policy (spec 07 §7.3.4.6)
// ---------------------------------------------------------------------------

/// Resolves the definition of `capability_uri` and its digest.
///
/// # Errors
///
/// [`TrustError::UnknownChallengeCapability`] if the URI does not parse, is
/// not in canonical form, or names an unknown protocol row; the source's
/// [`DefinitionError`](super::capability_definition::DefinitionError) mapped
/// into [`TrustError`]; [`TrustError::CapabilityDefinitionUnavailable`] if
/// the source returns a definition of another URI.
fn resolve_definition(
    defs: &dyn CapabilityDefinitionSource,
    capability_uri: &str,
) -> Result<(CapabilityDefinition, [u8; 32]), TrustError> {
    let unknown = || TrustError::UnknownChallengeCapability {
        uri: capability_uri.to_owned(),
    };
    let parsed = validate_capability_uri(capability_uri).map_err(|_| unknown())?;
    if parsed.to_string() != capability_uri {
        return Err(unknown());
    }
    let definition = defs.definition(&parsed)?;
    if definition.capability_uri != capability_uri {
        return Err(TrustError::CapabilityDefinitionUnavailable {
            uri: capability_uri.to_owned(),
        });
    }
    definition.validate()?;
    let digest = definition.digest()?;
    Ok((definition, digest))
}

/// A challenger's choice of retries and cooldown, within the definition's
/// limits: no more retries, and no shorter cooldown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyPick {
    /// Retries after the first attempt; at most the definition's.
    pub max_retries: u32,
    /// Seconds between graded attempts; at least the definition's.
    pub cooldown_secs: u32,
}

/// The signed policy of one challenge: the definition it follows and the
/// retries and cooldown within that definition's limits.
#[derive(Debug, Clone)]
pub struct ChallengePolicy {
    definition: CapabilityDefinition,
    definition_digest: [u8; 32],
    max_retries: u32,
    cooldown_secs: u32,
}

impl ChallengePolicy {
    /// Obtains the definition of `capability_uri` from `defs` and fixes the
    /// policy. With no `pick`, the definition's values apply; the threshold
    /// is always the definition's.
    ///
    /// # Errors
    ///
    /// As [`resolve_definition`], and [`TrustError::PolicyOutsideDefinition`]
    /// when `pick` asks for more retries or a shorter cooldown.
    pub fn resolve(
        defs: &dyn CapabilityDefinitionSource,
        capability_uri: &str,
        pick: Option<PolicyPick>,
    ) -> Result<Self, TrustError> {
        let (definition, definition_digest) = resolve_definition(defs, capability_uri)?;
        let pick = pick.unwrap_or(PolicyPick {
            max_retries: definition.max_retries,
            cooldown_secs: definition.cooldown_secs,
        });
        let outside = |reason: String| TrustError::PolicyOutsideDefinition {
            uri: capability_uri.to_owned(),
            reason,
        };
        if pick.max_retries > definition.max_retries {
            return Err(outside(format!(
                "max_retries {} exceeds the definition's {}",
                pick.max_retries, definition.max_retries
            )));
        }
        if pick.cooldown_secs < definition.cooldown_secs {
            return Err(outside(format!(
                "cooldown_secs {} is below the definition's {}",
                pick.cooldown_secs, definition.cooldown_secs
            )));
        }
        Ok(Self {
            definition,
            definition_digest,
            max_retries: pick.max_retries,
            cooldown_secs: pick.cooldown_secs,
        })
    }

    /// The definition followed.
    #[must_use]
    pub const fn definition(&self) -> &CapabilityDefinition {
        &self.definition
    }

    /// The definition's digest.
    #[must_use]
    pub const fn definition_digest(&self) -> [u8; 32] {
        self.definition_digest
    }

    /// The signed retry count.
    #[must_use]
    pub const fn max_retries(&self) -> u32 {
        self.max_retries
    }

    /// The signed cooldown.
    #[must_use]
    pub const fn cooldown_secs(&self) -> u32 {
        self.cooldown_secs
    }
}

// ---------------------------------------------------------------------------
// Issue
// ---------------------------------------------------------------------------

/// Checks the suite rules of spec 07 §7.3.4 that hold for every URI: a
/// non-empty list, unique `test_id`s, weights summing to `TOTAL_WEIGHT_BPS`,
/// and I-JSON in every `input` and `expected`. Returns the case count.
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
            invalid(format!(
                "test case {:?} expected does not serialize: {e}",
                case.test_id
            ))
        })?;
        for (field, value) in [("input", &case.input), ("expected", &expected)] {
            crate::jcs::require_i_json(value)
                .map_err(|v| invalid(format!("test case {:?} {field}: {v}", case.test_id)))?;
        }
    }
    if weight_sum != u64::from(TOTAL_WEIGHT_BPS) {
        return Err(invalid(format!(
            "weights sum to {weight_sum}, not {TOTAL_WEIGHT_BPS}"
        )));
    }
    Ok(count)
}

/// Checks the definition's minimum (spec 07 §7.3.4.3). Under
/// `PerCategory`, every category is a well-formed BCP 47 tag, and tags
/// differing only in ASCII case name one language (RFC 5646 §2.1.1).
fn check_minimum(
    uri: &str,
    min_cases: MinCases,
    test_cases: &[TestCase],
    count: u32,
) -> Result<(), TrustError> {
    match min_cases {
        MinCases::Total(minimum) if count < minimum => {
            Err(TrustError::ChallengeSuiteBelowMinimum {
                uri: uri.to_owned(),
                minimum,
                supplied: count,
                category: None,
            })
        }
        MinCases::Total(_) => Ok(()),
        MinCases::PerCategory(minimum) => {
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
            match per_category.into_iter().find(|(_, n)| *n < minimum) {
                Some((category, supplied)) => Err(TrustError::ChallengeSuiteBelowMinimum {
                    uri: uri.to_owned(),
                    minimum,
                    supplied,
                    category: Some(category),
                }),
                None => Ok(()),
            }
        }
    }
}

/// Parses `verifier` and `subject` canonically and refuses one key in both
/// roles.
fn parse_parties(
    verifier: &str,
    subject: &str,
) -> Result<(CanonicalIdentifier, CanonicalIdentifier), TrustError> {
    let verifier = CanonicalIdentifier::parse(verifier)?;
    let subject = CanonicalIdentifier::parse(subject)?;
    if verifier == subject {
        return Err(TrustError::SelfChallenge {
            identifier: subject.as_str().to_owned(),
        });
    }
    Ok((verifier, subject))
}

fn random_32() -> Result<[u8; 32], TrustError> {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut bytes).map_err(|e| {
        TrustError::ChallengeSigningFailed {
            reason: format!("OS random source failed: {e}"),
        }
    })?;
    Ok(bytes)
}

/// The inputs of [`challenge_request_unsigned`].
#[derive(Debug, Clone)]
pub struct NewChallenge {
    /// The challenger.
    pub verifier: DID,
    /// The subject.
    pub subject: DID,
    /// The cases, with their answers.
    pub test_cases: Vec<TestCase>,
    /// The challenger's current time, which becomes `created_at`.
    pub created_at: u64,
    /// `expires_at - created_at`, in `1..=MAX_CHALLENGE_WINDOW_SECS`.
    pub window_secs: u64,
    /// The context the challenge is administered in.
    pub context_id: String,
    /// The resolved policy; its definition names the capability URI.
    pub policy: ChallengePolicy,
}

/// Builds a challenge request for the verifier to sign, and the answer key
/// the challenger keeps.
///
/// Checks, in order:
/// 1. `verifier` and `subject` parse canonically
///    ([`TrustError::NonCanonicalIdentifier`]) and are different keys
///    ([`TrustError::SelfChallenge`]);
/// 2. the suite rules ([`TrustError::InvalidChallengeSuite`]);
/// 3. the definition's minimum ([`TrustError::ChallengeSuiteBelowMinimum`]);
/// 4. every `SchemaMatch` schema passes [`SchemaGate::admit`]
///    ([`TrustError::SchemaRejected`]);
/// 5. `0 < window_secs <= MAX_CHALLENGE_WINDOW_SECS` and
///    `window_secs >= cooldown_secs`, so a retry fits inside the window
///    ([`TrustError::ChallengeWindowInvalid`]).
///
/// The challenge id is drawn from the OS random source.
///
/// # Errors
///
/// The errors above; [`TrustError::ChallengeSigningFailed`] if the random
/// source fails; [`TrustError::CanonicalizationFailed`] if encoding fails.
pub fn challenge_request_unsigned(
    new: NewChallenge,
) -> Result<(UnsignedChallengeRequest, AnswerKey), TrustError> {
    parse_parties(&new.verifier, &new.subject)?;
    let uri = new.policy.definition.capability_uri.clone();
    let count = check_suite_rules(&new.test_cases)?;
    check_minimum(
        &uri,
        new.policy.definition.min_cases,
        &new.test_cases,
        count,
    )?;
    for case in &new.test_cases {
        if let ExpectedOutput::SchemaMatch { schema } = &case.expected {
            SchemaGate::admit(&case.test_id, schema)?;
        }
    }
    let cooldown_secs = u64::from(new.policy.cooldown_secs);
    let window_invalid = TrustError::ChallengeWindowInvalid {
        window_secs: new.window_secs,
        cooldown_secs,
        max_secs: MAX_CHALLENGE_WINDOW_SECS,
    };
    if new.window_secs == 0
        || new.window_secs > MAX_CHALLENGE_WINDOW_SECS
        || new.window_secs < cooldown_secs
    {
        return Err(window_invalid);
    }
    let expires_at = new
        .created_at
        .checked_add(new.window_secs)
        .ok_or(window_invalid)?;

    let challenge_id = random_32()?;
    let mut cases = Vec::with_capacity(new.test_cases.len());
    let mut expected = Vec::with_capacity(new.test_cases.len());
    for case in new.test_cases {
        cases.push(ChallengeCase {
            test_id: case.test_id,
            input: case.input,
            category: case.category,
            weight: case.weight,
        });
        expected.push(case.expected);
    }

    let request = ChallengeRequest {
        challenge_id,
        capability_uri: uri,
        definition_digest: new.policy.definition_digest,
        test_cases: cases,
        created_at: new.created_at,
        expires_at,
        max_retries: new.policy.max_retries,
        cooldown_secs: new.policy.cooldown_secs,
        pass_threshold_bps: new.policy.definition.pass_threshold_bps,
        context_id: new.context_id,
        verifier: new.verifier,
        subject: new.subject,
        verifier_signature: Vec::new(),
    };
    let digest = challenge_request_signing_digest(&request)?;
    Ok((
        UnsignedChallengeRequest { request, digest },
        AnswerKey { expected },
    ))
}

// ---------------------------------------------------------------------------
// Respond
// ---------------------------------------------------------------------------

/// Refuses a raw response above `MAX_CHALLENGE_RESPONSE_BYTES`, or whose
/// container nesting exceeds `MAX_CHALLENGE_JSON_DEPTH`. It scans bytes
/// only, so it runs before any parse.
///
/// # Errors
///
/// [`TrustError::ResponseTooLarge`].
pub fn check_response_bounds(raw: &[u8]) -> Result<(), TrustError> {
    if raw.len() > MAX_CHALLENGE_RESPONSE_BYTES {
        return Err(TrustError::ResponseTooLarge {
            reason: format!("{} bytes exceed {MAX_CHALLENGE_RESPONSE_BYTES}", raw.len()),
        });
    }
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in raw {
        if in_string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_CHALLENGE_JSON_DEPTH {
                    return Err(TrustError::ResponseTooLarge {
                        reason: format!("nesting exceeds depth {MAX_CHALLENGE_JSON_DEPTH}"),
                    });
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

/// Checks that `outputs` answer `cases` one for one, in order.
fn check_outputs(
    challenge_id: &[u8; 32],
    cases: &[ChallengeCase],
    outputs: &[TestOutput],
) -> Result<(), TrustError> {
    let mismatch = |reason: String| TrustError::OutputsMismatch {
        challenge_id: hex::encode(challenge_id),
        reason,
    };
    if outputs.len() != cases.len() {
        return Err(mismatch(format!(
            "{} outputs for {} cases",
            outputs.len(),
            cases.len()
        )));
    }
    for (i, (case, output)) in cases.iter().zip(outputs).enumerate() {
        if case.test_id != output.test_id {
            return Err(mismatch(format!(
                "output {i} answers {:?}, case {i} is {:?}",
                output.test_id, case.test_id
            )));
        }
    }
    Ok(())
}

fn verify_request_signature(
    request: &ChallengeRequest,
    resolver: &dyn ActiveKeyResolver,
) -> Result<[u8; 32], TrustError> {
    let digest = challenge_request_signing_digest(request)?;
    let key = resolver.resolve_active_key(&request.verifier)?;
    verify_ed25519_signature(&key, &digest, &request.verifier_signature)
        .map_err(|reason| TrustError::ChallengeRequestSignatureInvalid { reason })?;
    Ok(digest)
}

/// Builds the subject's response for signing.
///
/// Checks, in order:
/// 1. the request's verifier signature over `D`
///    ([`TrustError::ChallengeRequestSignatureInvalid`]);
/// 2. `request.subject` is `own_identifier` by key
///    ([`TrustError::ChallengeResponderMismatch`]), both parsed canonically;
/// 3. `created_at - skew <= now <= expires_at + skew`
///    ([`TrustError::ChallengeExpired`]);
/// 4. `1 <= attempt <= 1 + max_retries` ([`TrustError::AttemptOutOfOrder`],
///    [`TrustError::RetriesExhausted`]);
/// 5. one output per case, in order ([`TrustError::OutputsMismatch`]);
/// 6. the signed response's JSON fits [`check_response_bounds`].
///
/// # Errors
///
/// The errors above; a resolver error propagates unchanged.
pub fn challenge_response_unsigned(
    request: &ChallengeRequest,
    own_identifier: &str,
    attempt: u32,
    outputs: Vec<TestOutput>,
    resolver: &dyn ActiveKeyResolver,
    clock: &dyn Clock,
) -> Result<UnsignedChallengeResponse, TrustError> {
    let own = CanonicalIdentifier::parse(own_identifier)?;
    CanonicalIdentifier::parse(&request.verifier)?;
    let request_digest = verify_request_signature(request, resolver)?;
    if CanonicalIdentifier::parse(&request.subject)? != own {
        return Err(TrustError::ChallengeResponderMismatch {
            expected: own_identifier.to_owned(),
            got: request.subject.to_string(),
        });
    }
    let now = clock.now_secs();
    if now < request.created_at.saturating_sub(CHALLENGE_CLOCK_SKEW_SECS)
        || now > request.expires_at.saturating_add(CHALLENGE_CLOCK_SKEW_SECS)
    {
        return Err(TrustError::ChallengeExpired {
            challenge_id: hex::encode(request.challenge_id),
            now,
            created_at: request.created_at,
            expires_at: request.expires_at,
        });
    }
    check_attempt_range(&request.challenge_id, attempt, request.max_retries)?;
    check_outputs(&request.challenge_id, &request.test_cases, &outputs)?;

    let mut response = ChallengeResponse {
        challenge_id: request.challenge_id,
        request_digest,
        subject: request.subject.clone(),
        attempt,
        outputs,
        // The largest Ed25519 signature encoding, so the bound covers the
        // response as sent.
        subject_signature: vec![u8::MAX; 64],
    };
    let wire = serde_json::to_vec(&response).map_err(|e| TrustError::CanonicalizationFailed {
        reason: format!("response does not serialize: {e}"),
    })?;
    check_response_bounds(&wire)?;
    response.subject_signature = Vec::new();
    let digest = challenge_response_signing_digest(&response)?;
    Ok(UnsignedChallengeResponse { response, digest })
}

/// `1 <= attempt <= 1 + max_retries`.
fn check_attempt_range(
    challenge_id: &[u8; 32],
    attempt: u32,
    max_retries: u32,
) -> Result<(), TrustError> {
    if attempt == 0 {
        return Err(TrustError::AttemptOutOfOrder {
            challenge_id: hex::encode(challenge_id),
            attempt,
            expected: 1,
        });
    }
    let allowed = 1 + u64::from(max_retries);
    if u64::from(attempt) > allowed {
        return Err(TrustError::RetriesExhausted {
            challenge_id: hex::encode(challenge_id),
            attempt,
            allowed,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Authenticate
// ---------------------------------------------------------------------------

/// A response whose subject signature verified against the request it
/// answers. Only [`authenticate_challenge_response`] makes one, so
/// [`grade`] never sees an unauthenticated response.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticatedResponse<'a> {
    request: &'a ChallengeRequest,
    response: &'a ChallengeResponse,
    request_digest: [u8; 32],
    response_digest: [u8; 32],
}

impl<'a> AuthenticatedResponse<'a> {
    /// The request answered.
    #[must_use]
    pub const fn request(&self) -> &'a ChallengeRequest {
        self.request
    }

    /// The authenticated response.
    #[must_use]
    pub const fn response(&self) -> &'a ChallengeResponse {
        self.response
    }

    /// `D`, the request digest.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// `D_r`, the response digest the subject signed.
    #[must_use]
    pub const fn response_digest(&self) -> [u8; 32] {
        self.response_digest
    }
}

impl AuthenticatedResponse<'_> {
    /// Copies the authenticated pair into an owned value that can cross a
    /// task or mailbox boundary without losing the proof of authentication.
    #[must_use]
    pub fn to_owned_response(&self) -> OwnedAuthenticatedResponse {
        OwnedAuthenticatedResponse {
            request: self.request.clone(),
            response: self.response.clone(),
            request_digest: self.request_digest,
            response_digest: self.response_digest,
        }
    }
}

/// An [`AuthenticatedResponse`] that owns its request and response. Only
/// [`AuthenticatedResponse::to_owned_response`] makes one, so holding one
/// still proves the subject signature verified.
#[derive(Debug, Clone)]
pub struct OwnedAuthenticatedResponse {
    request: ChallengeRequest,
    response: ChallengeResponse,
    request_digest: [u8; 32],
    response_digest: [u8; 32],
}

impl OwnedAuthenticatedResponse {
    /// Borrows the pair as an [`AuthenticatedResponse`].
    #[must_use]
    pub const fn as_authenticated(&self) -> AuthenticatedResponse<'_> {
        AuthenticatedResponse {
            request: &self.request,
            response: &self.response,
            request_digest: self.request_digest,
            response_digest: self.response_digest,
        }
    }
}

/// Authenticates a response for grading. It reads no ledger and writes
/// nothing, so a forged response costs the real subject nothing.
///
/// Checks, in order:
/// 1. `response.challenge_id` and `response.request_digest` match `request`
///    ([`TrustError::OutputsMismatch`]);
/// 2. `request.verifier` is `challenger` by key
///    ([`TrustError::ChallengeVerifierMismatch`]);
/// 3. `response.subject` is `request.subject` by key
///    ([`TrustError::ChallengeResponderMismatch`]);
/// 4. the request's weights sum to `TOTAL_WEIGHT_BPS`
///    ([`TrustError::InvalidChallengeSuite`]);
/// 5. the subject's signature over `D_r` verifies against its `#active` key
///    ([`TrustError::ChallengeSignatureInvalid`]);
/// 6. one output per case, in order ([`TrustError::OutputsMismatch`]).
///
/// Every identifier is parsed canonically first
/// ([`TrustError::NonCanonicalIdentifier`]).
///
/// # Errors
///
/// The errors above; a resolver error propagates unchanged.
pub fn authenticate_challenge_response<'a>(
    request: &'a ChallengeRequest,
    response: &'a ChallengeResponse,
    challenger: &str,
    resolver: &dyn ActiveKeyResolver,
) -> Result<AuthenticatedResponse<'a>, TrustError> {
    let challenge_id = hex::encode(request.challenge_id);
    let request_digest = challenge_request_signing_digest(request)?;
    if response.challenge_id != request.challenge_id || response.request_digest != request_digest {
        return Err(TrustError::OutputsMismatch {
            challenge_id,
            reason: "the response names another challenge or request digest".to_owned(),
        });
    }
    let named_challenger = CanonicalIdentifier::parse(challenger)?;
    if CanonicalIdentifier::parse(&request.verifier)? != named_challenger {
        return Err(TrustError::ChallengeVerifierMismatch {
            expected: request.verifier.to_string(),
            got: challenger.to_owned(),
        });
    }
    if CanonicalIdentifier::parse(&response.subject)?
        != CanonicalIdentifier::parse(&request.subject)?
    {
        return Err(TrustError::ChallengeResponderMismatch {
            expected: request.subject.to_string(),
            got: response.subject.to_string(),
        });
    }
    let weight_sum: u64 = request
        .test_cases
        .iter()
        .map(|case| u64::from(case.weight))
        .sum();
    if weight_sum != u64::from(TOTAL_WEIGHT_BPS) {
        return Err(TrustError::InvalidChallengeSuite {
            reason: format!("weights sum to {weight_sum}, not {TOTAL_WEIGHT_BPS}"),
        });
    }
    let response_digest = challenge_response_signing_digest(response)?;
    let key = resolver.resolve_active_key(&response.subject)?;
    verify_ed25519_signature(&key, &response_digest, &response.subject_signature).map_err(
        |reason| TrustError::ChallengeSignatureInvalid {
            challenge_id: challenge_id.clone(),
            reason,
        },
    )?;
    check_outputs(
        &request.challenge_id,
        &request.test_cases,
        &response.outputs,
    )?;
    Ok(AuthenticatedResponse {
        request,
        response,
        request_digest,
        response_digest,
    })
}

// ---------------------------------------------------------------------------
// Grade
// ---------------------------------------------------------------------------

/// One case's result. The reason is kept by the challenger and returned to
/// the caller; it is never signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseResult {
    /// Whether the case passed.
    pub passed: bool,
    /// Why it failed, or the evaluator's reason.
    pub reason: Option<String>,
}

impl CaseResult {
    const fn pass() -> Self {
        Self {
            passed: true,
            reason: None,
        }
    }

    fn fail(reason: &str) -> Self {
        Self {
            passed: false,
            reason: Some(reason.to_owned()),
        }
    }
}

/// The result of grading one attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GradeOutcome {
    /// One result per case, in case order.
    pub per_case: Vec<CaseResult>,
    /// Sum of the weights of passed cases.
    pub score: u32,
    /// Number of passed cases.
    pub pass_count: u32,
    /// Number of cases.
    pub test_count: u32,
    /// `score >= pass_threshold_bps`.
    pub passed: bool,
    /// The smallest per-category case count, categories ASCII case-folded.
    pub min_category_cases: u32,
}

/// The haystacks of `ContainsAll` and `ContainsNone`: the output itself
/// when it is a string, else every decoded string leaf and object key.
fn string_haystacks(output: &serde_json::Value) -> Vec<&str> {
    let mut found = Vec::new();
    let mut stack = vec![output];
    while let Some(value) = stack.pop() {
        match value {
            serde_json::Value::String(s) => found.push(s.as_str()),
            serde_json::Value::Array(items) => stack.extend(items),
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    found.push(key.as_str());
                    stack.push(child);
                }
            }
            _ => {}
        }
    }
    found
}

/// Grades one authenticated attempt (spec 07 §7.3.4 step 3).
///
/// `schema_results` and `evals` hold the verdicts the caller computed
/// within the grading budget for `SchemaMatch` and `CustomEval` cases,
/// keyed by case index. A missing verdict means the budget ran out at that
/// case: it and every later case fail with reason `budget_exceeded`.
///
/// - `ExactMatch`: RFC 8785 bytes of output and answer are equal.
/// - `SchemaMatch`: `Fail` gives `schema_mismatch`, `BacktrackLimit` gives
///   `backtrack_limit`.
/// - `ContainsAll` / `ContainsNone`: byte-exact, case-sensitive substring
///   search over [`string_haystacks`].
///
/// Grading cannot fail. A key that does not hold one expected output per
/// case yields one result per expected output, and
/// [`challenge_verification_unsigned`] refuses that outcome.
#[must_use]
pub fn grade(
    auth: &AuthenticatedResponse<'_>,
    key: &AnswerKey,
    evals: &BTreeMap<usize, CaseResult>,
    schema_results: &BTreeMap<usize, SchemaVerdict>,
) -> GradeOutcome {
    let cases = &auth.request.test_cases;
    let mut cut_off = false;
    let mut per_case = Vec::with_capacity(cases.len());
    for (i, (expected, output)) in key.expected.iter().zip(&auth.response.outputs).enumerate() {
        if cut_off {
            per_case.push(CaseResult::fail("budget_exceeded"));
            continue;
        }
        let output = &output.output;
        let result = match expected {
            ExpectedOutput::ExactMatch { value } => {
                match (crate::jcs::to_vec(output), crate::jcs::to_vec(value)) {
                    (Ok(a), Ok(b)) if a == b => CaseResult::pass(),
                    _ => CaseResult::fail("mismatch"),
                }
            }
            ExpectedOutput::SchemaMatch { .. } => match schema_results.get(&i) {
                Some(SchemaVerdict::Pass) => CaseResult::pass(),
                Some(SchemaVerdict::Fail) => CaseResult::fail("schema_mismatch"),
                Some(SchemaVerdict::BacktrackLimit) => CaseResult::fail("backtrack_limit"),
                None => {
                    cut_off = true;
                    CaseResult::fail("budget_exceeded")
                }
            },
            ExpectedOutput::ContainsAll { required } => {
                let hay = string_haystacks(output);
                if required
                    .iter()
                    .all(|r| hay.iter().any(|h| h.contains(r.as_str())))
                {
                    CaseResult::pass()
                } else {
                    CaseResult::fail("missing_required")
                }
            }
            ExpectedOutput::ContainsNone { forbidden } => {
                let hay = string_haystacks(output);
                if forbidden
                    .iter()
                    .any(|f| hay.iter().any(|h| h.contains(f.as_str())))
                {
                    CaseResult::fail("forbidden_present")
                } else {
                    CaseResult::pass()
                }
            }
            ExpectedOutput::CustomEval { .. } => evals.get(&i).cloned().unwrap_or_else(|| {
                cut_off = true;
                CaseResult::fail("budget_exceeded")
            }),
        };
        per_case.push(result);
    }
    let mut score: u32 = 0;
    let mut pass_count: u32 = 0;
    let mut test_count: u32 = 0;
    for (case, result) in cases.iter().zip(&per_case) {
        test_count = test_count.saturating_add(1);
        if result.passed {
            score = score.saturating_add(case.weight);
            pass_count = pass_count.saturating_add(1);
        }
    }
    GradeOutcome {
        per_case,
        score,
        pass_count,
        test_count,
        passed: score >= auth.request.pass_threshold_bps,
        min_category_cases: min_category_cases(cases.iter().map(|c| c.category.as_str())),
    }
}

// ---------------------------------------------------------------------------
// Attempt ledger check
// ---------------------------------------------------------------------------

/// Why a challenge closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeClosure {
    /// An attempt passed.
    Passed,
    /// The last allowed attempt failed.
    Exhausted,
}

/// Whether `t` is strictly inside the window `(created_at, expires_at)`
/// (spec 07 §7.3.4 steps 3 and 5(c)). The ledger's attempt check, the record
/// builder and the consumer all use it, so the three cannot disagree on a
/// boundary.
const fn grading_time_in_window(created_at: u64, expires_at: u64, t: u64) -> bool {
    created_at < t && t < expires_at
}

/// What [`check_attempt`] reads from the challenger's ledger entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptLedgerView {
    /// The challenge.
    pub challenge_id: [u8; 32],
    /// The request's `created_at`.
    pub created_at: u64,
    /// The request's `expires_at`.
    pub expires_at: u64,
    /// The request's `max_retries`.
    pub max_retries: u32,
    /// The request's `cooldown_secs`.
    pub cooldown_secs: u32,
    /// The last graded attempt, 0 for none.
    pub last_attempt: u32,
    /// When the last attempt was graded.
    pub last_timestamp: Option<u64>,
    /// When the last grading fault was recorded.
    pub last_fault_at: Option<u64>,
    /// Set once the challenge closes.
    pub closed: Option<ChallengeClosure>,
}

/// Decides whether `attempt` may be graded at `now`. Pure, so the ledger's
/// begin and commit turns run the same check.
///
/// Checks, in order: the window `created_at < now < expires_at`
/// ([`TrustError::ChallengeExpired`]); not closed
/// ([`TrustError::ChallengeClosed`]); `attempt == last_attempt + 1`
/// ([`TrustError::AttemptOutOfOrder`]); `attempt <= 1 + max_retries`
/// ([`TrustError::RetriesExhausted`]); `now >= c + cooldown_secs`, where `c`
/// is the later of `last_timestamp` and `last_fault_at` and the sum
/// saturates ([`TrustError::CooldownActive`]).
///
/// # Errors
///
/// The errors above.
pub fn check_attempt(view: &AttemptLedgerView, attempt: u32, now: u64) -> Result<(), TrustError> {
    let challenge_id = || hex::encode(view.challenge_id);
    if !grading_time_in_window(view.created_at, view.expires_at, now) {
        return Err(TrustError::ChallengeExpired {
            challenge_id: challenge_id(),
            now,
            created_at: view.created_at,
            expires_at: view.expires_at,
        });
    }
    if view.closed.is_some() {
        return Err(TrustError::ChallengeClosed {
            challenge_id: challenge_id(),
        });
    }
    let expected = view.last_attempt.saturating_add(1);
    if attempt != expected {
        return Err(TrustError::AttemptOutOfOrder {
            challenge_id: challenge_id(),
            attempt,
            expected,
        });
    }
    check_attempt_range(&view.challenge_id, attempt, view.max_retries)?;
    if let Some(last) = view.last_timestamp.max(view.last_fault_at) {
        let retry_after = last.saturating_add(u64::from(view.cooldown_secs));
        if now < retry_after {
            return Err(TrustError::CooldownActive {
                challenge_id: challenge_id(),
                retry_after,
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Record
// ---------------------------------------------------------------------------

/// Builds the record for one graded attempt, for the verifier to sign.
/// `expires_at = timestamp + MAX_VERIFICATION_VALIDITY_SECS`.
///
/// # Errors
///
/// [`TrustError::ChallengeVerificationOutsideWindow`] if `timestamp` is not
/// strictly inside the request's window; [`TrustError::ChallengeVerificationInconsistent`]
/// if `outcome` does not belong to `auth`'s request;
/// [`TrustError::CanonicalizationFailed`] if encoding fails.
pub fn challenge_verification_unsigned(
    auth: &AuthenticatedResponse<'_>,
    outcome: &GradeOutcome,
    timestamp: u64,
) -> Result<UnsignedChallengeVerification, TrustError> {
    let request = auth.request;
    let attempt = auth.response.attempt;
    let verification_id = challenge_verification_id(
        &request.verifier,
        &request.subject,
        &request.capability_uri,
        &request.challenge_id,
        attempt,
        timestamp,
    )?;
    if !grading_time_in_window(request.created_at, request.expires_at, timestamp) {
        return Err(TrustError::ChallengeVerificationOutsideWindow {
            verification_id: hex::encode(verification_id),
            timestamp,
            created_at: request.created_at,
            expires_at: request.expires_at,
        });
    }
    if outcome.per_case.len() != request.test_cases.len()
        || outcome.passed != (outcome.score >= request.pass_threshold_bps)
    {
        return Err(TrustError::ChallengeVerificationInconsistent {
            verification_id: hex::encode(verification_id),
            reason: "the outcome was not graded from this request".to_owned(),
        });
    }
    let verification = ChallengeVerification {
        verification_id,
        verifier: request.verifier.clone(),
        subject: request.subject.clone(),
        capability_uri: request.capability_uri.clone(),
        definition_digest: request.definition_digest,
        suite_digest: challenge_suite_digest(&request.test_cases)?,
        challenge_id: request.challenge_id,
        attempt,
        response_digest: auth.response_digest,
        max_retries: request.max_retries,
        cooldown_secs: request.cooldown_secs,
        pass_threshold_bps: request.pass_threshold_bps,
        min_category_cases: outcome.min_category_cases,
        passed: outcome.passed,
        score: outcome.score,
        test_count: outcome.test_count,
        pass_count: outcome.pass_count,
        challenge_created_at: request.created_at,
        challenge_expires_at: request.expires_at,
        timestamp,
        expires_at: timestamp.saturating_add(MAX_VERIFICATION_VALIDITY_SECS),
        context_id: request.context_id.clone(),
        verifier_signature: Vec::new(),
    };
    let digest = challenge_verification_signing_digest(&verification)?;
    Ok(UnsignedChallengeVerification {
        verification,
        digest,
    })
}

// ---------------------------------------------------------------------------
// Consume
// ---------------------------------------------------------------------------

/// Checks steps (f) and (g): the attempt is within the signed retries, the
/// signed policy is within the definition's limits, the challenge window is
/// at least the definition's cooldown, and the counts meet its minimum.
fn check_record_policy(
    v: &ChallengeVerification,
    defs: &dyn CapabilityDefinitionSource,
) -> Result<(), TrustError> {
    let outside = |reason: String| TrustError::PolicyOutsideDefinition {
        uri: v.capability_uri.clone(),
        reason,
    };
    if v.attempt == 0 || u64::from(v.attempt) - 1 > u64::from(v.max_retries) {
        return Err(outside(format!(
            "attempt {} is outside 1..={} for max_retries {}",
            v.attempt,
            u64::from(v.max_retries) + 1,
            v.max_retries
        )));
    }
    let (def, digest) = resolve_definition(defs, &v.capability_uri)?;
    let minimum_met = match def.min_cases {
        MinCases::Total(k) => v.test_count >= k,
        MinCases::PerCategory(k) => v.min_category_cases >= k,
    };
    let failure = if v.definition_digest != digest {
        Some("definition_digest is not the definition's digest".to_owned())
    } else if v.pass_threshold_bps != def.pass_threshold_bps {
        Some(format!(
            "pass_threshold_bps {} is not the definition's {}",
            v.pass_threshold_bps, def.pass_threshold_bps
        ))
    } else if v.max_retries > def.max_retries {
        Some(format!(
            "max_retries {} exceeds the definition's {}",
            v.max_retries, def.max_retries
        ))
    } else if v.cooldown_secs < def.cooldown_secs {
        Some(format!(
            "cooldown_secs {} is below the definition's {}",
            v.cooldown_secs, def.cooldown_secs
        ))
    } else if v
        .challenge_expires_at
        .saturating_sub(v.challenge_created_at)
        < u64::from(def.cooldown_secs)
    {
        Some(format!(
            "challenge window {}..{} is shorter than the definition's cooldown_secs {}",
            v.challenge_created_at, v.challenge_expires_at, def.cooldown_secs
        ))
    } else if !minimum_met {
        Some(format!(
            "test_count {} / min_category_cases {} below the definition's {:?}",
            v.test_count, v.min_category_cases, def.min_cases
        ))
    } else if v.min_category_cases > v.test_count {
        Some("min_category_cases exceeds test_count".to_owned())
    } else {
        None
    };
    failure.map_or(Ok(()), |reason| Err(outside(reason)))
}

/// Verifies a [`ChallengeVerification`] record and binds it to a subject, a
/// context and the current time; the verify-on-ingest gate for records
/// from anyone.
///
/// `verifier`, `subject` and `expected_subject` are parsed canonically
/// first ([`TrustError::NonCanonicalIdentifier`]). Then, in order:
/// - (a) the signature over `D_v` against the verifier's `#active` key
///   ([`TrustError::ChallengeVerificationSignatureInvalid`]);
/// - (b) `verification_id` re-derives
///   ([`TrustError::ChallengeVerificationIdMismatch`]);
/// - (c) `challenge_created_at < timestamp < challenge_expires_at`
///   ([`TrustError::ChallengeVerificationOutsideWindow`]);
/// - (d) `timestamp <= now + CHALLENGE_CLOCK_SKEW_SECS`
///   ([`TrustError::ChallengeVerificationFromFuture`]);
/// - (e) `expires_at - timestamp <= MAX_VERIFICATION_VALIDITY_SECS`
///   ([`TrustError::ChallengeVerificationValidityTooLong`]);
/// - (f) and (g) the attempt within the signed retries, the policy within
///   the definition's limits, and the challenge window at least the
///   definition's cooldown ([`TrustError::PolicyOutsideDefinition`]; definition errors as
///   [`ChallengePolicy::resolve`]);
/// - (h) `passed == (score >= pass_threshold_bps)`, `score <=
///   TOTAL_WEIGHT_BPS`, `pass_count <= test_count`
///   ([`TrustError::ChallengeVerificationInconsistent`]);
/// - (i) `verifier != subject` by key ([`TrustError::SelfChallenge`]);
/// - (j) `subject` is `expected_subject` by key
///   ([`TrustError::ChallengeSubjectMismatch`]);
/// - (k) `context_id` is the target context
///   ([`TrustError::ChallengeContextMismatch`]);
/// - (l) `now < expires_at` ([`TrustError::ChallengeVerificationExpired`]).
///
/// # Errors
///
/// The errors above; a resolver error propagates unchanged.
pub fn verify_challenge_verification(
    v: &ChallengeVerification,
    resolver: &dyn ActiveKeyResolver,
    definitions: &dyn CapabilityDefinitionSource,
    target_context_id: &str,
    expected_subject: &str,
    clock: &dyn Clock,
) -> Result<(), TrustError> {
    let verifier = CanonicalIdentifier::parse(&v.verifier)?;
    let subject = CanonicalIdentifier::parse(&v.subject)?;
    let expected_canonical = CanonicalIdentifier::parse(expected_subject)?;
    let id_hex = hex::encode(v.verification_id);

    let digest = challenge_verification_signing_digest(v)?;
    let key = resolver.resolve_active_key(&v.verifier)?;
    verify_ed25519_signature(&key, &digest, &v.verifier_signature).map_err(|reason| {
        TrustError::ChallengeVerificationSignatureInvalid {
            verification_id: id_hex.clone(),
            reason,
        }
    })?;

    let expected_id = challenge_verification_id(
        &v.verifier,
        &v.subject,
        &v.capability_uri,
        &v.challenge_id,
        v.attempt,
        v.timestamp,
    )?;
    if v.verification_id != expected_id {
        return Err(TrustError::ChallengeVerificationIdMismatch {
            verification_id: id_hex,
            expected: hex::encode(expected_id),
        });
    }

    if !grading_time_in_window(v.challenge_created_at, v.challenge_expires_at, v.timestamp) {
        return Err(TrustError::ChallengeVerificationOutsideWindow {
            verification_id: id_hex,
            timestamp: v.timestamp,
            created_at: v.challenge_created_at,
            expires_at: v.challenge_expires_at,
        });
    }

    let now = clock.now_secs();
    if v.timestamp > now.saturating_add(CHALLENGE_CLOCK_SKEW_SECS) {
        return Err(TrustError::ChallengeVerificationFromFuture {
            verification_id: id_hex,
            timestamp: v.timestamp,
            now,
            skew_secs: CHALLENGE_CLOCK_SKEW_SECS,
        });
    }

    let validity_secs = v.expires_at.saturating_sub(v.timestamp);
    if validity_secs > MAX_VERIFICATION_VALIDITY_SECS {
        return Err(TrustError::ChallengeVerificationValidityTooLong {
            verification_id: id_hex,
            validity_secs,
            max_secs: MAX_VERIFICATION_VALIDITY_SECS,
        });
    }

    check_record_policy(v, definitions)?;

    if v.passed != (v.score >= v.pass_threshold_bps)
        || v.score > TOTAL_WEIGHT_BPS
        || v.pass_count > v.test_count
    {
        return Err(TrustError::ChallengeVerificationInconsistent {
            verification_id: id_hex,
            reason: format!(
                "passed {} with score {} of threshold {}, pass_count {} of {}",
                v.passed, v.score, v.pass_threshold_bps, v.pass_count, v.test_count
            ),
        });
    }

    if verifier == subject {
        return Err(TrustError::SelfChallenge {
            identifier: v.subject.to_string(),
        });
    }

    if subject != expected_canonical {
        return Err(TrustError::ChallengeSubjectMismatch {
            verification_id: id_hex,
            record_subject: v.subject.to_string(),
            expected_subject: expected_subject.to_owned(),
        });
    }

    if v.context_id != target_context_id {
        return Err(TrustError::ChallengeContextMismatch {
            verification_id: id_hex,
            record_context: v.context_id.clone(),
            expected_context: target_context_id.to_owned(),
        });
    }

    if v.expires_at <= now {
        return Err(TrustError::ChallengeVerificationExpired {
            verification_id: id_hex,
            expires_at: v.expires_at,
            now,
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Test and fixture signing
// ---------------------------------------------------------------------------

/// Signs a 32-byte digest with an Ed25519 key. Test and fixture use only;
/// production signs through the party's custody.
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
    new: NewChallenge,
    signer: &(impl ChallengeSigner + ?Sized),
) -> Result<(ChallengeRequest, AnswerKey), TrustError> {
    let (unsigned, key) = challenge_request_unsigned(new)?;
    let signature = signer.sign(&unsigned.signing_digest())?;
    Ok((unsigned.with_verifier_signature(signature), key))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::trust::challenge_fixtures::{
        CONTEXT, FIXTURE_URI, Fixture, NOW, PROTOCOL_URI, case, cases, cases_in, fixture,
        fixture_definition,
    };

    // -----------------------------------------------------------------------
    // Spec 25 vectors 59-62
    // -----------------------------------------------------------------------

    const V_VERIFIER: &str = "scp:vsrmsobf2uzejsbdaag3txwauasjrpnt5wlkulhahbbfwtdfaapa";
    const V_SUBJECT: &str = "scp:ktarg6aqtsju6mh2ws3hk7t5kmsvmckq7d5eqwsmaw5di3e3p4ta";
    const V_DEFINITION_DIGEST: &str =
        "1947de3173cb08e14fa71bd41bb256274ba2b62e0d0d9e73b83af1a971ee8f67";

    fn v_cid() -> [u8; 32] {
        std::array::from_fn(|i| u8::try_from(i + 1).unwrap())
    }

    /// Spec 25 Vector 59 `T`.
    const V_T: &str = "0000000100000015736368656d612d76616c69646174696f6e2d3030310000001b7b22636f756e74223a332c226e616d65223a22776964676574227d00000006736368656d6100002710";
    /// Spec 25 Vector 59 `R`.
    const V_R: &str = "5343502d4348414c4c454e47452d5245512d56313a0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000587363703a7466676969616f33367a6c73656f32747a666f6933326b6e667836746f7070656433716c6f7863737562653567647666727167713a6361706162696c6974793a736368656d612d76616c69646174696f6e2f76311947de3173cb08e14fa71bd41bb256274ba2b62e0d0d9e73b83af1a971ee8f670000000100000015736368656d612d76616c69646174696f6e2d3030310000001b7b22636f756e74223a332c226e616d65223a22776964676574227d00000006736368656d6100002710000000006553f10000000000655542800000000200000e1000001f400000000f746573742d636f6e746578742d3031000000387363703a7673726d736f626632757a656a73626461616733747877617561736a72706e7435776c6b756c6861686262667774646661617061000000387363703a6b7461726736617174736a75366d6832777333686b3774356b6d73766d636b71376435657177736d617735646933653370347461";

    fn v_request() -> ChallengeRequest {
        ChallengeRequest {
            challenge_id: v_cid(),
            capability_uri: FIXTURE_URI.to_owned(),
            definition_digest: fixture_definition().digest().unwrap(),
            test_cases: vec![ChallengeCase {
                test_id: "schema-validation-001".to_owned(),
                input: json!({"name": "widget", "count": 3}),
                category: "schema".to_owned(),
                weight: 10_000,
            }],
            created_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            max_retries: 2,
            cooldown_secs: 3600,
            pass_threshold_bps: 8000,
            context_id: "test-context-01".to_owned(),
            verifier: DID::from(V_VERIFIER),
            subject: DID::from(V_SUBJECT),
            verifier_signature: Vec::new(),
        }
    }

    fn v_response(attempt: u32, output: Value) -> ChallengeResponse {
        ChallengeResponse {
            challenge_id: v_cid(),
            request_digest: challenge_request_signing_digest(&v_request()).unwrap(),
            subject: DID::from(V_SUBJECT),
            attempt,
            outputs: vec![TestOutput {
                test_id: "schema-validation-001".to_owned(),
                output,
            }],
            subject_signature: Vec::new(),
        }
    }

    fn v_record(attempt: u32, timestamp: u64, passed: bool) -> ChallengeVerification {
        let response = if attempt == 1 {
            v_response(1, json!({"name": "widget"}))
        } else {
            v_response(2, json!({"count": 3, "name": "widget"}))
        };
        let request = v_request();
        ChallengeVerification {
            verification_id: challenge_verification_id(
                V_VERIFIER,
                V_SUBJECT,
                FIXTURE_URI,
                &v_cid(),
                attempt,
                timestamp,
            )
            .unwrap(),
            verifier: DID::from(V_VERIFIER),
            subject: DID::from(V_SUBJECT),
            capability_uri: FIXTURE_URI.to_owned(),
            definition_digest: request.definition_digest,
            suite_digest: challenge_suite_digest(&request.test_cases).unwrap(),
            challenge_id: v_cid(),
            attempt,
            response_digest: challenge_response_signing_digest(&response).unwrap(),
            max_retries: 2,
            cooldown_secs: 3600,
            pass_threshold_bps: 8000,
            min_category_cases: 1,
            passed,
            score: if passed { 10_000 } else { 0 },
            test_count: 1,
            pass_count: u32::from(passed),
            challenge_created_at: 1_700_000_000,
            challenge_expires_at: 1_700_086_400,
            timestamp,
            expires_at: timestamp + MAX_VERIFICATION_VALIDITY_SECS,
            context_id: "test-context-01".to_owned(),
            verifier_signature: Vec::new(),
        }
    }

    /// Test 1.
    #[test]
    fn vector_59_challenge_request() {
        let request = v_request();
        assert_eq!(hex::encode(request.definition_digest), V_DEFINITION_DIGEST);
        let r = canonical_challenge_request_bytes(&request).unwrap();
        assert_eq!(r.len(), 418);
        assert_eq!(
            hex::encode(challenge_request_signing_digest(&request).unwrap()),
            "bf8a8adb49daf2eb0078296f1a4bd29a637b992aa1c795cf930a863978c0e7e2"
        );
    }

    /// Test 2.
    #[test]
    fn vector_59_suite_digest() {
        let request = v_request();
        assert_eq!(
            test_cases_field_bytes(&request.test_cases).unwrap().len(),
            74
        );
        assert_eq!(
            hex::encode(challenge_suite_digest(&request.test_cases).unwrap()),
            "9cec9fc1c4c6a8a835e448fd94c33310692514aa51c4b52d2ba2d4a819f13cd8"
        );
    }

    /// The request preimage and its `T` match spec 25 byte for byte: each
    /// case ends at its weight, with no commitment and no byte derived from
    /// the expected output (spec 07 §7.3.4).
    #[test]
    fn request_preimage_has_no_commitment() {
        let request = v_request();
        let t = test_cases_field_bytes(&request.test_cases).unwrap();
        assert_eq!(hex::encode(&t), V_T);
        let r = canonical_challenge_request_bytes(&request).unwrap();
        assert_eq!(hex::encode(&r), V_R);
        let expected = ExpectedOutput::SchemaMatch {
            schema: json!({"type": "object", "required": ["name", "count"]}),
        };
        let expected = crate::jcs::to_vec(&expected).unwrap();
        assert!(!r.windows(expected.len()).any(|w| w == expected));
    }

    /// Test 3.
    #[test]
    fn vector_62_challenge_response() {
        let attempt_1 = v_response(1, json!({"name": "widget"}));
        let p1 = canonical_challenge_response_bytes(&attempt_1).unwrap();
        assert_eq!(p1.len(), 200);
        assert_eq!(
            hex::encode(&p1),
            "5343502d4348414c4c454e47452d524553502d56313a0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20bf8a8adb49daf2eb0078296f1a4bd29a637b992aa1c795cf930a863978c0e7e2000000387363703a6b7461726736617174736a75366d6832777333686b3774356b6d73766d636b71376435657177736d617735646933653370347461000000010000000100000015736368656d612d76616c69646174696f6e2d303031000000117b226e616d65223a22776964676574227d"
        );
        assert_eq!(
            hex::encode(challenge_response_signing_digest(&attempt_1).unwrap()),
            "e2d6a7768d281382acb3573e23ba9c76f58c07509c2f7727a151b589a687a185"
        );
        let attempt_2 = v_response(2, json!({"count": 3, "name": "widget"}));
        assert_eq!(
            canonical_challenge_response_bytes(&attempt_2)
                .unwrap()
                .len(),
            210
        );
        assert_eq!(
            hex::encode(challenge_response_signing_digest(&attempt_2).unwrap()),
            "f6e06ef6438935719b8b784119b6f75e8095ea27ffdfb8c60efc1c88bddb4949"
        );
    }

    /// Test 4.
    #[test]
    fn vector_60_61_record_matches_spec() {
        for (attempt, timestamp, passed, vid, d_v) in [
            (
                1,
                1_700_000_600,
                false,
                "9554fd256e3c6bb5ee6c73e1ca28e72ade44785bde24d84c17869cb1da667b77",
                "b4c5366bb9a106b8819cb974e602a6490a9b1b3f862497a6def7764d5bfa162d",
            ),
            (
                2,
                1_700_004_200,
                true,
                "5cec3cdef9ef548b71a346c713eead24381a8cac1e0d422e1a788cf524d99d63",
                "765bf9ca092df576175ae942aae2a0cc501fba5f899a96dbd065157f5e6c0fa3",
            ),
        ] {
            let record = v_record(attempt, timestamp, passed);
            assert_eq!(hex::encode(record.verification_id), vid);
            assert_eq!(
                canonical_challenge_verification_bytes(&record)
                    .unwrap()
                    .len(),
                480
            );
            assert_eq!(
                hex::encode(challenge_verification_signing_digest(&record).unwrap()),
                d_v
            );
        }
    }

    /// The challenge separators spec 09 §9.18.2 registers are exactly the
    /// ones this module hashes under: a row the code no longer uses, or a
    /// separator the registry lacks, fails.
    #[test]
    fn challenge_domain_separators_match_spec_09_registry() {
        const SPEC_09: &str = include_str!("../../../../.docs/specs/09-security-model.md");
        let start = SPEC_09.find("#### 9.18.2 Domain Separators").unwrap();
        let end = start + SPEC_09[start..].find("#### 9.18.3").unwrap();
        let registered: std::collections::BTreeSet<&str> = SPEC_09[start..end]
            .lines()
            .filter_map(|line| line.strip_prefix("| `\"SCP-CHALLENGE-"))
            .filter_map(|rest| rest.split_once("\"`").map(|(name, _)| name))
            .collect();
        let used: std::collections::BTreeSet<&str> = [
            DOMAIN_CHALLENGE_REQ_V1,
            DOMAIN_CHALLENGE_RESP_V1,
            DOMAIN_CHALLENGE_VERIFY_V1,
        ]
        .iter()
        .map(|d| {
            std::str::from_utf8(d)
                .unwrap()
                .strip_prefix("SCP-CHALLENGE-")
                .unwrap()
        })
        .collect();
        assert_eq!(registered, used);
        assert!(!SPEC_09.contains("SCP-CHALLENGE-COMMIT"));
    }

    /// Test 6.
    #[test]
    fn request_wire_has_no_expected() {
        let fx = fixture();
        let mut suite = cases(2);
        suite[0].expected = ExpectedOutput::ContainsAll {
            required: vec!["secret-answer".to_owned()],
        };
        let (request, key) = fx.issue(FIXTURE_URI, suite).unwrap();
        let wire = serde_json::to_string(&request).unwrap();
        assert!(!wire.contains("expected"), "{wire}");
        assert!(!wire.contains("secret-answer"), "{wire}");
        assert!(!wire.contains("ContainsAll"), "{wire}");
        assert!(!format!("{key:?}").contains("secret-answer"));
        assert_eq!(key.expected().len(), 2);
    }

    // -----------------------------------------------------------------------
    // Grading
    // -----------------------------------------------------------------------

    /// Issues `suite`, answers with `outputs`, authenticates and grades.
    fn graded(
        fx: &Fixture,
        suite: Vec<TestCase>,
        outputs: Vec<Value>,
        evals: &BTreeMap<usize, CaseResult>,
        schemas: &BTreeMap<usize, SchemaVerdict>,
    ) -> GradeOutcome {
        let (request, key) = fx.issue(FIXTURE_URI, suite).unwrap();
        let outputs = request
            .test_cases
            .iter()
            .zip(outputs)
            .map(|(c, output)| TestOutput {
                test_id: c.test_id.clone(),
                output,
            })
            .collect();
        let response = fx.respond(&request, 1, outputs).unwrap();
        let auth =
            authenticate_challenge_response(&request, &response, &fx.verifier.did, &fx.resolver)
                .unwrap();
        grade(&auth, &key, evals, schemas)
    }

    fn one_case(expected: ExpectedOutput) -> Vec<TestCase> {
        let mut suite = vec![case("only", "general", 10_000)];
        suite[0].expected = expected;
        suite
    }

    fn grade_one(expected: ExpectedOutput, output: Value) -> CaseResult {
        let fx = fixture();
        let outcome = graded(
            &fx,
            one_case(expected),
            vec![output],
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        outcome.per_case[0].clone()
    }

    /// RFC 8785 equality, not `to_string` equality (`1.0` and `1`
    /// print differently and canonicalize alike).
    #[test]
    fn grade_exact_match_is_jcs_equality() {
        let answer = ExpectedOutput::ExactMatch {
            value: json!({"b": 1.0, "a": [1, 2]}),
        };
        let output: Value = serde_json::from_str(r#"{"a":[1,2],"b":1}"#).unwrap();
        assert_ne!(
            output.to_string(),
            json!({"b": 1.0, "a": [1, 2]}).to_string()
        );
        assert!(grade_one(answer.clone(), output).passed);
        let wrong = grade_one(answer, json!({"a": [2, 1], "b": 1}));
        assert!(!wrong.passed);
        assert_eq!(wrong.reason.as_deref(), Some("mismatch"));
    }

    /// Test 8d.
    #[test]
    fn grade_backtrack_limit_fails_the_case() {
        let fx = fixture();
        let schema = ExpectedOutput::SchemaMatch {
            schema: json!({"type": "string"}),
        };
        let mut suite = cases(2);
        suite[0].expected = schema.clone();
        suite[1].expected = schema;
        let schemas =
            BTreeMap::from([(0, SchemaVerdict::BacktrackLimit), (1, SchemaVerdict::Pass)]);
        let outcome = graded(
            &fx,
            suite,
            vec![json!("x"), json!("y")],
            &BTreeMap::new(),
            &schemas,
        );
        assert!(!outcome.per_case[0].passed);
        assert_eq!(
            outcome.per_case[0].reason.as_deref(),
            Some("backtrack_limit")
        );
        assert!(outcome.per_case[1].passed);
        assert_eq!(outcome.pass_count, 1);
    }

    /// Grading is total: a missing schema or evaluator verdict fails that
    /// case and every later case with `budget_exceeded`, and never passes.
    #[test]
    fn grade_is_total() {
        let fx = fixture();
        for missing in [
            ExpectedOutput::SchemaMatch {
                schema: json!({"type": "string"}),
            },
            ExpectedOutput::CustomEval {
                evaluator_outlet_id: "fixture-evaluator".to_owned(),
            },
        ] {
            let mut suite = cases(3);
            suite[1].expected = missing;
            let outcome = graded(
                &fx,
                suite,
                vec![json!("ok"), json!("x"), json!("ok")],
                &BTreeMap::new(),
                &BTreeMap::new(),
            );
            assert_eq!(outcome.per_case.len(), 3);
            assert!(outcome.per_case[0].passed);
            for result in &outcome.per_case[1..] {
                assert!(!result.passed);
                assert_eq!(result.reason.as_deref(), Some("budget_exceeded"));
            }
        }
    }

    /// Test 8f (response half; the schema half is in `schema_gate`).
    #[test]
    fn response_over_cap_refused() {
        let big = vec![b' '; MAX_CHALLENGE_RESPONSE_BYTES + 1];
        assert!(matches!(
            check_response_bounds(&big),
            Err(TrustError::ResponseTooLarge { .. })
        ));
        check_response_bounds(&big[1..]).unwrap();
        let deep = "[".repeat(MAX_CHALLENGE_JSON_DEPTH + 1);
        assert!(matches!(
            check_response_bounds(deep.as_bytes()),
            Err(TrustError::ResponseTooLarge { .. })
        ));
        let at_cap = format!(
            "{}{}",
            "[".repeat(MAX_CHALLENGE_JSON_DEPTH),
            "]".repeat(MAX_CHALLENGE_JSON_DEPTH)
        );
        check_response_bounds(at_cap.as_bytes()).unwrap();
        // Brackets inside strings, including after an escaped quote, do
        // not count.
        let quoted = format!("[\"\\\"{}\"]", "[".repeat(MAX_CHALLENGE_JSON_DEPTH * 2));
        check_response_bounds(quoted.as_bytes()).unwrap();
    }

    /// Test 9.
    #[test]
    fn grade_contains_on_decoded_leaves() {
        let quoted = ExpectedOutput::ContainsAll {
            required: vec!["\"hi\"".to_owned()],
        };
        assert!(grade_one(quoted, json!({"msg": "say \"hi\""})).passed);
        let key = ExpectedOutput::ContainsAll {
            required: vec!["needle".to_owned()],
        };
        assert!(grade_one(key, json!({"outer": [{"needle": 1}]})).passed);
        // Numbers are not haystacks, though JCS(output) contains "7".
        let number = ExpectedOutput::ContainsAll {
            required: vec!["7".to_owned()],
        };
        let result = grade_one(number, json!({"n": 7}));
        assert!(!result.passed);
        assert_eq!(result.reason.as_deref(), Some("missing_required"));
    }

    /// Test 10.
    #[test]
    fn grade_contains_none_case_sensitive() {
        let forbidden = ExpectedOutput::ContainsNone {
            forbidden: vec!["Secret".to_owned()],
        };
        assert!(grade_one(forbidden.clone(), json!("a secret")).passed);
        let result = grade_one(forbidden, json!({"k": ["a Secret"]}));
        assert!(!result.passed);
        assert_eq!(result.reason.as_deref(), Some("forbidden_present"));
    }

    /// The score, not the pass count, decides.
    #[test]
    fn grade_score_weighted_threshold() {
        let fx = fixture();
        let suite = vec![
            case("heavy", "general", 9000),
            case("light", "general", 1000),
        ];
        let outcome = graded(
            &fx,
            suite.clone(),
            vec![json!("ok"), json!("no")],
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        assert_eq!(
            (outcome.score, outcome.pass_count, outcome.test_count),
            (9000, 1, 2)
        );
        assert!(outcome.passed);
        let outcome = graded(
            &fx,
            suite,
            vec![json!("no"), json!("ok")],
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        assert_eq!(outcome.score, 1000);
        assert!(!outcome.passed);
    }

    /// Test 11b.
    #[test]
    fn min_category_cases_case_folds() {
        assert_eq!(min_category_cases(["en", "EN", "fr"]), 1);
        assert_eq!(min_category_cases(["en", "EN", "fr", "Fr"]), 2);
        assert_eq!(min_category_cases(std::iter::empty()), 0);
    }

    /// Grading has no error path. A key that holds fewer expected outputs
    /// than the request has cases grades to an outcome with fewer results,
    /// and the record builder refuses that outcome, so nothing is signed.
    #[test]
    fn short_key_grades_but_the_record_is_refused() {
        let fx = fixture();
        let (request, key) = fx.issue(FIXTURE_URI, cases(2)).unwrap();
        let outputs = request
            .test_cases
            .iter()
            .map(|c| TestOutput {
                test_id: c.test_id.clone(),
                output: json!("ok"),
            })
            .collect();
        let response = fx.respond(&request, 1, outputs).unwrap();
        let auth =
            authenticate_challenge_response(&request, &response, &fx.verifier.did, &fx.resolver)
                .unwrap();
        let mut short = key;
        short.expected.pop();
        let outcome = grade(&auth, &short, &BTreeMap::new(), &BTreeMap::new());
        assert_eq!(outcome.per_case.len(), 1);
        assert!(matches!(
            challenge_verification_unsigned(&auth, &outcome, request.created_at + 1),
            Err(TrustError::ChallengeVerificationInconsistent { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Attempt checks
    // -----------------------------------------------------------------------

    fn view() -> AttemptLedgerView {
        AttemptLedgerView {
            challenge_id: [7; 32],
            created_at: NOW,
            expires_at: NOW + 3600,
            max_retries: 2,
            cooldown_secs: 300,
            last_attempt: 0,
            last_timestamp: None,
            last_fault_at: None,
            closed: None,
        }
    }

    /// T5: the window is strict at both ends (RULING 5) in all three checks
    /// that read it: the ledger's attempt check, the record builder and the
    /// consumer's step (c). The table is `created`, `created + 1`,
    /// `expires - 1` and `expires`.
    #[test]
    fn grading_window_is_strict_in_all_three_checks() {
        let fx = fixture();
        let (request, key) = fx.issue(FIXTURE_URI, cases(2)).unwrap();
        let outputs = request
            .test_cases
            .iter()
            .map(|c| TestOutput {
                test_id: c.test_id.clone(),
                output: json!("ok"),
            })
            .collect();
        let response = fx.respond(&request, 1, outputs).unwrap();
        let auth =
            authenticate_challenge_response(&request, &response, &fx.verifier.did, &fx.resolver)
                .unwrap();
        let outcome = grade(&auth, &key, &BTreeMap::new(), &BTreeMap::new());
        let (created, expires) = (request.created_at, request.expires_at);
        let ledger = AttemptLedgerView {
            challenge_id: request.challenge_id,
            created_at: created,
            expires_at: expires,
            max_retries: request.max_retries,
            cooldown_secs: request.cooldown_secs,
            ..view()
        };
        let genuine = challenge_verification_unsigned(&auth, &outcome, created + 1).unwrap();
        for (t, inside) in [
            (created, false),
            (created + 1, true),
            (expires - 1, true),
            (expires, false),
        ] {
            let checked = check_attempt(&ledger, 1, t);
            assert_eq!(checked.is_ok(), inside, "check_attempt at {t}: {checked:?}");
            assert!(
                inside || matches!(checked, Err(TrustError::ChallengeExpired { .. })),
                "{checked:?}"
            );
            let built = challenge_verification_unsigned(&auth, &outcome, t);
            assert_eq!(built.is_ok(), inside, "record builder at {t}");
            assert!(
                inside
                    || matches!(
                        built,
                        Err(TrustError::ChallengeVerificationOutsideWindow { .. })
                    )
            );
            // The consumer: the genuine record restamped at `t`, its id
            // re-derived and re-signed, read at `t`.
            let mut record = genuine.record().clone();
            record.timestamp = t;
            record.expires_at = t + MAX_VERIFICATION_VALIDITY_SECS;
            record.verification_id = challenge_verification_id(
                &record.verifier,
                &record.subject,
                &record.capability_uri,
                &record.challenge_id,
                record.attempt,
                t,
            )
            .unwrap();
            fx.resign(&mut record).unwrap();
            fx.clock.set(t);
            let consumed = verify(&fx, &record);
            assert_eq!(consumed.is_ok(), inside, "consumer at {t}: {consumed:?}");
            assert!(
                inside
                    || matches!(
                        consumed,
                        Err(TrustError::ChallengeVerificationOutsideWindow { .. })
                    )
            );
        }
    }

    #[test]
    fn check_attempt_enforces_order_retries_cooldown_and_closure() {
        let after_one = AttemptLedgerView {
            last_attempt: 1,
            last_timestamp: Some(NOW + 10),
            ..view()
        };
        assert!(matches!(
            check_attempt(&after_one, 1, NOW + 400),
            Err(TrustError::AttemptOutOfOrder { expected: 2, .. })
        ));
        assert!(matches!(
            check_attempt(&after_one, 2, NOW + 309),
            Err(TrustError::CooldownActive { retry_after, .. }) if retry_after == NOW + 310
        ));
        check_attempt(&after_one, 2, NOW + 310).unwrap();
        let after_three = AttemptLedgerView {
            last_attempt: 3,
            ..after_one
        };
        assert!(matches!(
            check_attempt(&after_three, 4, NOW + 1000),
            Err(TrustError::RetriesExhausted { allowed: 3, .. })
        ));
        for closure in [ChallengeClosure::Passed, ChallengeClosure::Exhausted] {
            let closed = AttemptLedgerView {
                closed: Some(closure),
                ..view()
            };
            assert!(matches!(
                check_attempt(&closed, 1, NOW + 1),
                Err(TrustError::ChallengeClosed { .. })
            ));
        }
    }

    /// T8 (design call (i)): a fault starts the cooldown and closes
    /// nothing, and the cooldown runs from the later of the last attempt and
    /// the last fault.
    #[test]
    fn check_attempt_cooldown_runs_from_the_later_of_attempt_and_fault() {
        let faulted = AttemptLedgerView {
            last_fault_at: Some(NOW + 10),
            ..view()
        };
        assert!(matches!(
            check_attempt(&faulted, 1, NOW + 309),
            Err(TrustError::CooldownActive { retry_after, .. }) if retry_after == NOW + 310
        ));
        check_attempt(&faulted, 1, NOW + 310).unwrap();
        for (attempt_at, fault_at) in [(NOW + 10, NOW + 50), (NOW + 50, NOW + 10)] {
            let both = AttemptLedgerView {
                last_attempt: 1,
                last_timestamp: Some(attempt_at),
                last_fault_at: Some(fault_at),
                ..view()
            };
            assert!(matches!(
                check_attempt(&both, 2, NOW + 349),
                Err(TrustError::CooldownActive { retry_after, .. }) if retry_after == NOW + 350
            ));
            check_attempt(&both, 2, NOW + 350).unwrap();
        }
    }

    // -----------------------------------------------------------------------
    // Consume
    // -----------------------------------------------------------------------

    fn verify(fx: &Fixture, record: &ChallengeVerification) -> Result<(), TrustError> {
        verify_challenge_verification(
            record,
            &fx.resolver,
            &fx.definitions,
            CONTEXT,
            &fx.subject.did,
            &fx.clock,
        )
    }

    /// A genuine record for `FIXTURE_URI` with two cases.
    fn record(fx: &Fixture) -> ChallengeVerification {
        fx.genuine_record(FIXTURE_URI, cases(2)).unwrap()
    }

    /// Applies `edit`, re-derives the id and re-signs with the genuine key.
    fn edited(
        fx: &Fixture,
        edit: impl FnOnce(&mut ChallengeVerification),
    ) -> ChallengeVerification {
        let mut v = record(fx);
        edit(&mut v);
        v.verification_id = challenge_verification_id(
            &v.verifier,
            &v.subject,
            &v.capability_uri,
            &v.challenge_id,
            v.attempt,
            v.timestamp,
        )
        .unwrap();
        fx.resign(&mut v).unwrap();
        v
    }

    #[test]
    fn genuine_record_verifies() {
        let fx = fixture();
        let v = record(&fx);
        verify(&fx, &v).unwrap();
        assert!(v.passed);
        assert_eq!((v.score, v.test_count, v.pass_count), (10_000, 2, 2));
        assert_eq!(v.expires_at, NOW + 1 + MAX_VERIFICATION_VALIDITY_SECS);
    }

    /// Test 16.
    #[test]
    fn verify_rejects_timestamp_outside_window() {
        let fx = fixture();
        let late = edited(&fx, |v| {
            v.challenge_expires_at = v.timestamp - 1;
        });
        assert!(matches!(
            verify(&fx, &late),
            Err(TrustError::ChallengeVerificationOutsideWindow { .. })
        ));
        let early = edited(&fx, |v| {
            v.challenge_created_at = v.timestamp + 1;
        });
        assert!(matches!(
            verify(&fx, &early),
            Err(TrustError::ChallengeVerificationOutsideWindow { .. })
        ));
    }

    /// Test 17.
    #[test]
    fn verify_rejects_future_timestamp() {
        let fx = fixture();
        let skew = CHALLENGE_CLOCK_SKEW_SECS;
        // The window stays at least the definition's cooldown (step (g)) and
        // strictly contains the timestamp (step (c)).
        let window_end = NOW + skew + u64::from(fixture_definition().cooldown_secs);
        let at_edge = edited(&fx, |v| {
            v.timestamp = NOW + skew;
            v.challenge_expires_at = window_end;
            v.expires_at = v.timestamp + 1;
        });
        verify(&fx, &at_edge).unwrap();
        let future = edited(&fx, |v| {
            v.timestamp = NOW + skew + 1;
            v.challenge_expires_at = window_end;
            v.expires_at = v.timestamp + 1;
        });
        assert!(matches!(
            verify(&fx, &future),
            Err(TrustError::ChallengeVerificationFromFuture { .. })
        ));
    }

    #[test]
    fn verify_rejects_validity_over_max() {
        let fx = fixture();
        let long = edited(&fx, |v| v.expires_at += 1);
        assert!(matches!(
            verify(&fx, &long),
            Err(TrustError::ChallengeVerificationValidityTooLong { .. })
        ));
    }

    fn assert_outside(fx: &Fixture, v: &ChallengeVerification, what: &str) {
        assert!(
            matches!(
                verify(fx, v),
                Err(TrustError::PolicyOutsideDefinition { .. })
            ),
            "{what}: {:?}",
            verify(fx, v)
        );
    }

    /// Test 18.
    #[test]
    fn verify_rejects_attempt_beyond_max() {
        let fx = fixture();
        assert_outside(
            &fx,
            &edited(&fx, |v| v.attempt = v.max_retries + 2),
            "attempt",
        );
        assert_outside(&fx, &edited(&fx, |v| v.attempt = 0), "attempt 0");
        // The last allowed attempt passes.
        verify(&fx, &edited(&fx, |v| v.attempt = v.max_retries + 1)).unwrap();
    }

    /// Test 19.
    #[test]
    fn verify_rejects_record_outside_definition() {
        let mut fx = fixture();
        assert_outside(
            &fx,
            &edited(&fx, |v| v.pass_threshold_bps = 8001),
            "threshold",
        );
        assert_outside(&fx, &edited(&fx, |v| v.max_retries = 3), "retries");
        assert_outside(&fx, &edited(&fx, |v| v.cooldown_secs = 3599), "cooldown");
        assert_outside(&fx, &edited(&fx, |v| v.definition_digest[0] ^= 1), "digest");
        assert_outside(
            &fx,
            &edited(&fx, |v| v.min_category_cases = v.test_count + 1),
            "min_category_cases > test_count",
        );
        // A stricter policy is inside the definition.
        verify(&fx, &edited(&fx, |v| v.cooldown_secs = 7200)).unwrap();

        let genuine = record(&fx);
        fx.definitions.fixture_override = Some(CapabilityDefinition {
            min_cases: MinCases::Total(3),
            ..fixture_definition()
        });
        let mut short = genuine.clone();
        short.definition_digest = fx
            .definitions
            .fixture_override
            .as_ref()
            .unwrap()
            .digest()
            .unwrap();
        fx.resign(&mut short).unwrap();
        assert_outside(&fx, &short, "Total short");

        fx.definitions.fixture_override = Some(CapabilityDefinition {
            min_cases: MinCases::PerCategory(2),
            ..fixture_definition()
        });
        let mut per_category = genuine;
        per_category.min_category_cases = 1;
        per_category.definition_digest = fx
            .definitions
            .fixture_override
            .as_ref()
            .unwrap()
            .digest()
            .unwrap();
        fx.resign(&mut per_category).unwrap();
        assert_outside(&fx, &per_category, "PerCategory short");
    }

    /// Test 20.
    #[test]
    fn verify_rejects_passed_score_mismatch() {
        let fx = fixture();
        for (what, edit) in [
            (
                "passed below threshold",
                (|v: &mut ChallengeVerification| v.score = 7999) as fn(&mut ChallengeVerification),
            ),
            ("failed above threshold", |v| v.passed = false),
            ("score above total", |v| v.score = TOTAL_WEIGHT_BPS + 1),
            ("pass_count above test_count", |v| v.pass_count = 3),
        ] {
            assert!(
                matches!(
                    verify(&fx, &edited(&fx, edit)),
                    Err(TrustError::ChallengeVerificationInconsistent { .. })
                ),
                "{what}"
            );
        }
    }

    /// Test 21.
    #[test]
    fn noncanonical_identifier_refused_and_self_challenge_by_key() {
        let fx = fixture();
        let alias = fx.subject.padding_alias();
        assert_ne!(alias, fx.subject.did.0.as_str());
        let noncanonical = |r: Result<(), TrustError>| {
            assert!(
                matches!(r, Err(TrustError::NonCanonicalIdentifier { .. })),
                "{r:?}"
            );
        };

        // Create.
        let mut new = fx.new_challenge(FIXTURE_URI, cases(2), None).unwrap();
        new.subject = DID::from(alias.as_str());
        noncanonical(challenge_request_unsigned(new).map(|_| ()));

        // Grade: the challenger names itself by an alias.
        let (request, _key) = fx.issue(FIXTURE_URI, cases(2)).unwrap();
        let outputs = request
            .test_cases
            .iter()
            .map(|c| TestOutput {
                test_id: c.test_id.clone(),
                output: json!("ok"),
            })
            .collect();
        let response = fx.respond(&request, 1, outputs).unwrap();
        let verifier_alias = fx.verifier.padding_alias();
        noncanonical(
            authenticate_challenge_response(&request, &response, &verifier_alias, &fx.resolver)
                .map(|_| ()),
        );

        // Consume: the expected subject by alias, and a record naming one.
        let v = record(&fx);
        noncanonical(verify_challenge_verification(
            &v,
            &fx.resolver,
            &fx.definitions,
            CONTEXT,
            &alias,
            &fx.clock,
        ));
        noncanonical(verify(
            &fx,
            &edited(&fx, |v| v.subject = DID::from(alias.as_str())),
        ));

        // Self-challenge: the subject is the verifier's key in another form.
        let same_key = DID::from(format!("did:key:{}", hex::encode(fx.verifier.public())));
        let mut new = fx.new_challenge(FIXTURE_URI, cases(2), None).unwrap();
        new.subject = same_key.clone();
        assert!(matches!(
            challenge_request_unsigned(new),
            Err(TrustError::SelfChallenge { .. })
        ));
        let mut resolver_fx = fixture();
        resolver_fx.resolver.insert(&same_key, fx.verifier.public());
        let self_record = edited(&resolver_fx, |v| v.subject = same_key.clone());
        assert!(matches!(
            verify_challenge_verification(
                &self_record,
                &resolver_fx.resolver,
                &resolver_fx.definitions,
                CONTEXT,
                &same_key,
                &resolver_fx.clock,
            ),
            Err(TrustError::SelfChallenge { .. })
        ));
    }

    /// A named edit of one record field.
    type Mutation = (&'static str, fn(&mut ChallengeVerification));

    /// Each of the 22 signed fields of `R_v` is covered.
    #[test]
    fn verify_rejects_each_signed_field_altered() {
        let fx = fixture();
        let genuine = record(&fx);
        let base = canonical_challenge_verification_bytes(&genuine).unwrap();
        let mutations: [Mutation; 22] = [
            ("verification_id", |v| v.verification_id[0] ^= 1),
            ("verifier", |v| v.verifier = DID::from("did:dht:x")),
            ("subject", |v| v.subject = DID::from("did:dht:x")),
            ("capability_uri", |v| v.capability_uri.push('x')),
            ("definition_digest", |v| v.definition_digest[0] ^= 1),
            ("suite_digest", |v| v.suite_digest[0] ^= 1),
            ("challenge_id", |v| v.challenge_id[0] ^= 1),
            ("attempt", |v| v.attempt += 1),
            ("response_digest", |v| v.response_digest[0] ^= 1),
            ("max_retries", |v| v.max_retries += 1),
            ("cooldown_secs", |v| v.cooldown_secs += 1),
            ("pass_threshold_bps", |v| v.pass_threshold_bps += 1),
            ("min_category_cases", |v| v.min_category_cases += 1),
            ("passed", |v| v.passed = !v.passed),
            ("score", |v| v.score += 1),
            ("test_count", |v| v.test_count += 1),
            ("pass_count", |v| v.pass_count += 1),
            ("challenge_created_at", |v| v.challenge_created_at += 1),
            ("challenge_expires_at", |v| v.challenge_expires_at += 1),
            ("timestamp", |v| v.timestamp += 1),
            ("expires_at", |v| v.expires_at += 1),
            ("context_id", |v| v.context_id.push('x')),
        ];
        for (field, mutate) in mutations {
            let mut v = genuine.clone();
            mutate(&mut v);
            assert_ne!(
                canonical_challenge_verification_bytes(&v).unwrap(),
                base,
                "{field} is not in R_v"
            );
            let err = verify(&fx, &v).unwrap_err();
            assert!(
                matches!(
                    err,
                    TrustError::ChallengeVerificationSignatureInvalid { .. }
                        | TrustError::NonCanonicalIdentifier { .. }
                ),
                "{field}: {err:?}"
            );
        }
    }

    #[test]
    fn verify_rejects_wrong_subject_context_and_expired() {
        let fx = fixture();
        let v = record(&fx);
        assert!(matches!(
            verify_challenge_verification(
                &v,
                &fx.resolver,
                &fx.definitions,
                CONTEXT,
                &fx.other.did,
                &fx.clock
            ),
            Err(TrustError::ChallengeSubjectMismatch { .. })
        ));
        assert!(matches!(
            verify_challenge_verification(
                &v,
                &fx.resolver,
                &fx.definitions,
                "ctx-2",
                &fx.subject.did,
                &fx.clock
            ),
            Err(TrustError::ChallengeContextMismatch { .. })
        ));
        fx.clock.set(v.expires_at);
        assert!(matches!(
            verify(&fx, &v),
            Err(TrustError::ChallengeVerificationExpired { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Create
    // -----------------------------------------------------------------------

    /// RULING 15(b): any `u32` retry count and cooldown is a valid
    /// definition and policy, and the attempt check saturates instead of
    /// overflowing when the cooldown runs past the end of time.
    #[test]
    fn definition_accepts_u32_max_retries_and_u32_max_cooldown() {
        let mut fx = fixture();
        let mut definition = fixture_definition();
        definition.max_retries = u32::MAX;
        definition.cooldown_secs = u32::MAX;
        definition.validate().unwrap();
        fx.definitions.fixture_override = Some(definition);
        let policy = ChallengePolicy::resolve(&fx.definitions, FIXTURE_URI, None).unwrap();
        assert_eq!(
            (policy.max_retries(), policy.cooldown_secs()),
            (u32::MAX, u32::MAX)
        );
        let last = u64::MAX - 10;
        let view = AttemptLedgerView {
            challenge_id: [7; 32],
            created_at: 0,
            expires_at: u64::MAX,
            max_retries: u32::MAX,
            cooldown_secs: u32::MAX,
            last_attempt: u32::MAX - 1,
            last_timestamp: Some(last),
            last_fault_at: None,
            closed: None,
        };
        assert!(matches!(
            check_attempt(&view, u32::MAX, last + 1),
            Err(TrustError::CooldownActive {
                retry_after: u64::MAX,
                ..
            })
        ));
        // With no prior attempt, the last allowed attempt number passes the
        // range check: 1 + u32::MAX does not wrap.
        let first = AttemptLedgerView {
            last_attempt: 0,
            last_timestamp: None,
            ..view
        };
        check_attempt(&first, 1, 1).unwrap();
        check_attempt_range(&[7; 32], u32::MAX, u32::MAX).unwrap();
    }

    /// Test 19b.
    #[test]
    fn create_accepts_stricter_policy_refuses_looser() {
        let fx = fixture();
        let pick = |max_retries, cooldown_secs| {
            ChallengePolicy::resolve(
                &fx.definitions,
                FIXTURE_URI,
                Some(PolicyPick {
                    max_retries,
                    cooldown_secs,
                }),
            )
        };
        let strict = pick(0, 7200).unwrap();
        assert_eq!((strict.max_retries(), strict.cooldown_secs()), (0, 7200));
        pick(2, 3600).unwrap();
        // RULING 15(b): no protocol ceiling on the cooldown.
        pick(2, u32::MAX).unwrap();
        for (max_retries, cooldown) in [(3, 3600), (2, 3599)] {
            assert!(
                matches!(
                    pick(max_retries, cooldown),
                    Err(TrustError::PolicyOutsideDefinition { .. })
                ),
                "{max_retries} {cooldown}"
            );
        }
        let default = ChallengePolicy::resolve(&fx.definitions, FIXTURE_URI, None).unwrap();
        assert_eq!((default.max_retries(), default.cooldown_secs()), (2, 3600));
        // The signed request carries the stricter pick and the threshold.
        let new = NewChallenge {
            policy: strict,
            window_secs: 7200,
            ..fx.new_challenge(FIXTURE_URI, cases(2), None).unwrap()
        };
        let (unsigned, _) = challenge_request_unsigned(new).unwrap();
        let request = unsigned.request();
        assert_eq!(
            (
                request.max_retries,
                request.cooldown_secs,
                request.pass_threshold_bps
            ),
            (0, 7200, 8000)
        );
        assert_eq!(
            request.definition_digest,
            fixture_definition().digest().unwrap()
        );
    }

    /// Test 23.
    #[test]
    fn request_rejects_window_over_max() {
        let fx = fixture();
        for window_secs in [0, MAX_CHALLENGE_WINDOW_SECS + 1] {
            let new = NewChallenge {
                window_secs,
                ..fx.new_challenge(FIXTURE_URI, cases(2), None).unwrap()
            };
            assert!(matches!(
                challenge_request_unsigned(new),
                Err(TrustError::ChallengeWindowInvalid { .. })
            ));
        }
        let new = NewChallenge {
            window_secs: MAX_CHALLENGE_WINDOW_SECS,
            ..fx.new_challenge(FIXTURE_URI, cases(2), None).unwrap()
        };
        let (unsigned, _) = challenge_request_unsigned(new).unwrap();
        assert_eq!(
            unsigned.request().expires_at,
            NOW + MAX_CHALLENGE_WINDOW_SECS
        );
        let new = NewChallenge {
            created_at: u64::MAX,
            ..fx.new_challenge(FIXTURE_URI, cases(2), None).unwrap()
        };
        assert!(matches!(
            challenge_request_unsigned(new),
            Err(TrustError::ChallengeWindowInvalid { .. })
        ));
    }

    /// T7 (design call (iii)): a window shorter than the policy's cooldown
    /// is refused at Create; a window equal to it is accepted.
    #[test]
    fn request_rejects_window_shorter_than_cooldown() {
        let fx = fixture();
        let template = fx.new_challenge(FIXTURE_URI, cases(2), None).unwrap();
        let cooldown = u64::from(template.policy.cooldown_secs());
        let short = NewChallenge {
            window_secs: cooldown - 1,
            ..fx.new_challenge(FIXTURE_URI, cases(2), None).unwrap()
        };
        assert!(matches!(
            challenge_request_unsigned(short),
            Err(TrustError::ChallengeWindowInvalid { window_secs, cooldown_secs, .. })
                if window_secs == cooldown - 1 && cooldown_secs == cooldown
        ));
        let equal = NewChallenge {
            window_secs: cooldown,
            ..template
        };
        challenge_request_unsigned(equal).unwrap();
    }

    /// T7 (design call (iii)): consume step (g) refuses a record whose
    /// challenge window is shorter than the definition's cooldown.
    #[test]
    fn verify_rejects_window_shorter_than_definition_cooldown() {
        let fx = fixture();
        let cooldown = u64::from(fixture_definition().cooldown_secs);
        let short = edited(&fx, |v| {
            v.challenge_expires_at = v.challenge_created_at + cooldown - 1;
        });
        assert!(matches!(
            verify(&fx, &short),
            Err(TrustError::PolicyOutsideDefinition { .. })
        ));
        let equal = edited(&fx, |v| {
            v.challenge_expires_at = v.challenge_created_at + cooldown;
        });
        verify(&fx, &equal).unwrap();
    }

    /// Test 24.
    #[test]
    fn create_rejects_policy_outside_definition() {
        let fx = fixture();
        // A protocol row: Total(20).
        assert!(matches!(
            fx.issue(PROTOCOL_URI, cases(19)),
            Err(TrustError::ChallengeSuiteBelowMinimum {
                minimum: 20,
                supplied: 19,
                ..
            })
        ));
        let (request, _) = fx.issue(PROTOCOL_URI, cases(20)).unwrap();
        assert_eq!(
            (
                request.pass_threshold_bps,
                request.max_retries,
                request.cooldown_secs
            ),
            (9500, 2, 300)
        );
        assert!(matches!(
            ChallengePolicy::resolve(
                &fx.definitions,
                PROTOCOL_URI,
                Some(PolicyPick {
                    max_retries: 3,
                    cooldown_secs: 300
                })
            ),
            Err(TrustError::PolicyOutsideDefinition { .. })
        ));
        // Multilingual: five per BCP 47 category, case-folded.
        let multilingual = "scp:capability:multilingual/v1";
        fx.issue(multilingual, cases_in(&[("en", 5), ("fr", 5)]))
            .unwrap();
        assert!(matches!(
            fx.issue(multilingual, cases_in(&[("en", 5), ("fr", 4)])),
            Err(TrustError::ChallengeSuiteBelowMinimum { .. })
        ));
        assert!(matches!(
            fx.issue(multilingual, cases_in(&[("en", 5), ("not a tag", 5)])),
            Err(TrustError::InvalidChallengeSuite { .. })
        ));
        // Suite rules.
        let mut repeated = cases(2);
        repeated[1].test_id = repeated[0].test_id.clone();
        assert!(matches!(
            fx.issue(FIXTURE_URI, repeated),
            Err(TrustError::InvalidChallengeSuite { .. })
        ));
        let mut light = cases(2);
        light[0].weight -= 1;
        assert!(matches!(
            fx.issue(FIXTURE_URI, light),
            Err(TrustError::InvalidChallengeSuite { .. })
        ));
        assert!(matches!(
            fx.issue(FIXTURE_URI, Vec::new()),
            Err(TrustError::InvalidChallengeSuite { .. })
        ));
        // A non-canonical URI spelling.
        assert!(matches!(
            ChallengePolicy::resolve(
                &fx.definitions,
                "scp:capability:schema-validation/v01",
                None
            ),
            Err(TrustError::UnknownChallengeCapability { .. })
        ));
        // An inadmissible schema.
        let mut remote = cases(2);
        remote[0].expected = ExpectedOutput::SchemaMatch {
            schema: json!({"$ref": "https://example.com/s.json"}),
        };
        assert!(matches!(
            fx.issue(FIXTURE_URI, remote),
            Err(TrustError::SchemaRejected { .. })
        ));
    }

    /// Test 40 at create: no source defines an identifier-scoped URI but
    /// the fixture's.
    #[test]
    fn identifier_scoped_uri_fails_closed_at_create() {
        let fx = fixture();
        let other =
            "scp:fqhx6rdyx2knwadygeppkg5dzsmtinrlb4ku3s7zywlvolsgz4za:capability:anything/v1";
        assert!(matches!(
            ChallengePolicy::resolve(&fx.definitions, other, None),
            Err(TrustError::CapabilityDefinitionUnavailable { .. })
        ));
        assert!(matches!(
            ChallengePolicy::resolve(
                &super::super::capability_definition::ProtocolOnlyDefinitions,
                FIXTURE_URI,
                None
            ),
            Err(TrustError::CapabilityDefinitionUnavailable { .. })
        ));
    }

    /// Each of the 28 protocol rows, across all 10 categories: a gradable
    /// row refuses a suite one case below its minimum and, at the minimum,
    /// yields a record that verifies with the row's signed policy; a refused
    /// row is refused at create.
    #[test]
    fn every_protocol_capability_challenges_at_its_minimum() {
        use super::super::capability_registry::{Grading, protocol_capabilities};
        let fx = fixture();
        let mut categories = HashSet::new();
        let mut seen = 0;
        for (uri, entry) in protocol_capabilities() {
            seen += 1;
            categories.insert(entry.category.as_str());
            let standard = entry.challenge.unwrap();
            if standard.grading == Grading::Refused {
                assert!(
                    matches!(
                        ChallengePolicy::resolve(&fx.definitions, uri, None),
                        Err(TrustError::StandardNotGradable { .. })
                    ),
                    "{uri}"
                );
                continue;
            }
            let (at_minimum, below) = match standard.min_cases {
                MinCases::Total(n) => {
                    assert!(n >= 2, "{uri}: a one-case minimum has no suite below it");
                    (cases(n), cases(n - 1))
                }
                MinCases::PerCategory(n) => (
                    cases_in(&[("en", n), ("fr", n)]),
                    cases_in(&[("en", n), ("fr", n - 1)]),
                ),
            };
            assert!(
                matches!(
                    fx.issue(uri, below),
                    Err(TrustError::ChallengeSuiteBelowMinimum { .. })
                ),
                "{uri}"
            );
            let count = u32::try_from(at_minimum.len()).unwrap();
            let v = fx
                .genuine_record(uri, at_minimum)
                .unwrap_or_else(|e| panic!("{uri}: {e:?}"));
            verify(&fx, &v).unwrap_or_else(|e| panic!("{uri}: {e:?}"));
            assert_eq!(
                (
                    v.test_count,
                    v.pass_threshold_bps,
                    v.max_retries,
                    u64::from(v.cooldown_secs)
                ),
                (
                    count,
                    standard.pass_threshold_bps,
                    standard.max_retries,
                    u64::from(standard.cooldown_secs)
                ),
                "{uri}"
            );
        }
        assert_eq!(seen, 28);
        assert_eq!(categories.len(), 10);
    }

    /// Test 41.
    #[test]
    fn refused_standards_refused_at_create_and_consume() {
        let fx = fixture();
        for uri in [
            "scp:capability:rate-limit-compliance/v1",
            "scp:capability:latency-compliance/v1",
            "scp:capability:cost-awareness/v1",
            "scp:capability:code-generation/v1",
            "scp:capability:code-review/v1",
            "scp:system:relay-operation",
        ] {
            assert!(
                matches!(
                    ChallengePolicy::resolve(&fx.definitions, uri, None),
                    Err(TrustError::StandardNotGradable { .. })
                ),
                "{uri}"
            );
            let v = edited(&fx, |v| v.capability_uri = uri.to_owned());
            assert!(
                matches!(verify(&fx, &v), Err(TrustError::StandardNotGradable { .. })),
                "{uri}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Respond and authenticate
    // -----------------------------------------------------------------------

    fn ok_outputs(request: &ChallengeRequest) -> Vec<TestOutput> {
        request
            .test_cases
            .iter()
            .map(|c| TestOutput {
                test_id: c.test_id.clone(),
                output: json!("ok"),
            })
            .collect()
    }

    /// Test 25.
    #[test]
    fn respond_rejects_wrong_subject_closed_window_count() {
        let fx = fixture();
        let (request, _) = fx.issue(FIXTURE_URI, cases(2)).unwrap();
        let respond = |own: &str, attempt, outputs| {
            challenge_response_unsigned(&request, own, attempt, outputs, &fx.resolver, &fx.clock)
                .map(|_| ())
        };
        respond(&fx.subject.did, 1, ok_outputs(&request)).unwrap();
        assert!(matches!(
            respond(&fx.other.did, 1, ok_outputs(&request)),
            Err(TrustError::ChallengeResponderMismatch { .. })
        ));
        let mut short = ok_outputs(&request);
        short.pop();
        assert!(matches!(
            respond(&fx.subject.did, 1, short),
            Err(TrustError::OutputsMismatch { .. })
        ));
        let mut swapped = ok_outputs(&request);
        swapped.swap(0, 1);
        assert!(matches!(
            respond(&fx.subject.did, 1, swapped),
            Err(TrustError::OutputsMismatch { .. })
        ));
        assert!(matches!(
            respond(&fx.subject.did, 0, ok_outputs(&request)),
            Err(TrustError::AttemptOutOfOrder { .. })
        ));
        assert!(matches!(
            respond(&fx.subject.did, 4, ok_outputs(&request)),
            Err(TrustError::RetriesExhausted { .. })
        ));
        let mut forged = request.clone();
        forged.max_retries = 0;
        assert!(matches!(
            challenge_response_unsigned(
                &forged,
                &fx.subject.did,
                1,
                ok_outputs(&request),
                &fx.resolver,
                &fx.clock
            ),
            Err(TrustError::ChallengeRequestSignatureInvalid { .. })
        ));
        fx.clock
            .set(request.expires_at + CHALLENGE_CLOCK_SKEW_SECS + 1);
        assert!(matches!(
            respond(&fx.subject.did, 1, ok_outputs(&request)),
            Err(TrustError::ChallengeExpired { .. })
        ));
        fx.clock.set(request.expires_at + CHALLENGE_CLOCK_SKEW_SECS);
        respond(&fx.subject.did, 1, ok_outputs(&request)).unwrap();
        let mut huge = ok_outputs(&request);
        huge[0].output = json!("x".repeat(MAX_CHALLENGE_RESPONSE_BYTES));
        assert!(matches!(
            respond(&fx.subject.did, 1, huge),
            Err(TrustError::ResponseTooLarge { .. })
        ));
    }

    #[test]
    fn authenticate_refuses_forgeries_before_grading() {
        let fx = fixture();
        let (request, _) = fx.issue(FIXTURE_URI, cases(2)).unwrap();
        let response = fx.respond(&request, 1, ok_outputs(&request)).unwrap();
        let auth = |req: &ChallengeRequest, resp: &ChallengeResponse, challenger: &str| {
            authenticate_challenge_response(req, resp, challenger, &fx.resolver)
                .map(|a| (a.request_digest(), a.response_digest()))
        };
        let (d, d_r) = auth(&request, &response, &fx.verifier.did).unwrap();
        assert_eq!(d, challenge_request_signing_digest(&request).unwrap());
        assert_eq!(d_r, challenge_response_signing_digest(&response).unwrap());

        let mut forged = response.clone();
        forged.outputs[0].output = json!("changed");
        assert!(matches!(
            auth(&request, &forged, &fx.verifier.did),
            Err(TrustError::ChallengeSignatureInvalid { .. })
        ));
        let mut other_digest = response.clone();
        other_digest.request_digest[0] ^= 1;
        assert!(matches!(
            auth(&request, &other_digest, &fx.verifier.did),
            Err(TrustError::OutputsMismatch { .. })
        ));
        assert!(matches!(
            auth(&request, &response, &fx.other.did),
            Err(TrustError::ChallengeVerifierMismatch { .. })
        ));
        let mut by_other = response.clone();
        by_other.subject = fx.other.did.clone();
        assert!(matches!(
            auth(&request, &by_other, &fx.verifier.did),
            Err(TrustError::ChallengeResponderMismatch { .. })
        ));
        // A response the other party signs for the subject fails the
        // signature check.
        let mut other_signed = response.clone();
        other_signed.subject_signature = super::super::challenge_fixtures::Party::new(3)
            .sign(&challenge_response_signing_digest(&response).unwrap())
            .unwrap();
        assert!(matches!(
            auth(&request, &other_signed, &fx.verifier.did),
            Err(TrustError::ChallengeSignatureInvalid { .. })
        ));
    }

    #[test]
    fn record_refuses_timestamp_outside_window() {
        let fx = fixture();
        let (request, key) = fx.issue(FIXTURE_URI, cases(2)).unwrap();
        let response = fx.respond(&request, 1, ok_outputs(&request)).unwrap();
        let auth =
            authenticate_challenge_response(&request, &response, &fx.verifier.did, &fx.resolver)
                .unwrap();
        let outcome = grade(&auth, &key, &BTreeMap::new(), &BTreeMap::new());
        challenge_verification_unsigned(&auth, &outcome, request.expires_at - 1).unwrap();
        for timestamp in [
            request.created_at - 1,
            request.created_at,
            request.expires_at,
            request.expires_at + 1,
        ] {
            assert!(matches!(
                challenge_verification_unsigned(&auth, &outcome, timestamp),
                Err(TrustError::ChallengeVerificationOutsideWindow { .. })
            ));
        }
    }
}
