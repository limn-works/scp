//! The owner's pure half of `09-security-model.md` §9.3.1, "What the owner's
//! SDK does": the Play Integrity verdict request and response, the 176-byte
//! verdict assembled from a response, the owner's run of Play Integrity checks
//! 1 through 6 before it publishes, the two entries' `serviceEndpoint`
//! strings, and the renewal deadline.
//!
//! Nothing here performs I/O or publishes. The effectful producer in
//! `scp-runtime` sends the [`VerdictRequest`] body, hands the response's status
//! and body to [`VerdictResponse::from_http`], and publishes only a string
//! that [`play_integrity_entry_endpoint`] or [`app_attest_entry_endpoint`]
//! returns. [`play_integrity_entry_endpoint`] takes a [`CheckedVerdict`], which
//! only [`check_play_integrity_verdict`] builds and only after every check
//! passes, so a response that yields no passing verdict yields nothing to
//! publish. [`app_attest_entry_endpoint`] re-encodes the attestation object
//! itself, so no non-canonical object reaches an entry.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use scp_did::Identifier;
use scp_kel::ResolvedState;
use serde::{Deserialize, Serialize};

use super::cbor::{AppAttestObjectError, canonicalize_app_attest_object};
use super::digest::{device_attestation_binding_digest, device_attestation_tag};
use super::play_integrity::{
    PlayIntegrityFailure, PlayIntegrityRead, VERDICT_LEN, run_play_integrity_checks,
};
use super::{DeviceAttestationRejection, DeviceAttestationUnverifiable};
use crate::crypto::canonical::CanonicalError;
use crate::trust::sybil::ValidatedSybilPolicy;

/// The longest integrity token, in UTF-8 bytes, a verdict request carries
/// (§9.3.1, "The verdict request").
pub const MAX_VERDICT_TOKEN_LEN: usize = 16_384;

/// The longest verdict request body a verifier accepts (§9.3.1). The owner
/// sends no body longer than this.
pub const MAX_VERDICT_REQUEST_LEN: usize = 32_768;

/// The longest canonical verdict response body.
///
/// It is the six members with each timestamp at 2^53, the largest integer JCS
/// writes exactly. Every longer body is not the canonical serialization of a
/// six-member response.
pub const MAX_VERDICT_RESPONSE_LEN: usize = 358;

/// The body a verifier answers `422` with (§9.3.1, "The verdict response").
pub const VERDICT_REFUSED_BODY: &[u8] = br#"{"error":"verdict_refused"}"#;

/// The HTTP status of a verdict.
const STATUS_OK: u16 = 200;

/// The HTTP status of a refusal.
const STATUS_REFUSED: u16 = 422;

/// The `serviceEndpoint` platform tag of an App Attest entry.
const APP_ATTEST_TAG: &str = "app-attest";

/// The `serviceEndpoint` platform tag of a Play Integrity entry.
const PLAY_INTEGRITY_TAG: &str = "play-integrity";

/// The challenge procedure step 1 reads as unset.
const UNSET_CHALLENGE: [u8; 32] = [0; 32];

/// The challenge of a policy that weights the signal, or `None` while the
/// policy's challenge is unset (procedure step 1), when no entry can verify.
fn set_challenge(policy: ValidatedSybilPolicy<'_>) -> Option<&[u8; 32]> {
    let challenge = &policy.policy().device_attestation_challenge;
    (*challenge != UNSET_CHALLENGE).then_some(challenge)
}

/// What a verdict request covers.
#[derive(Debug, Clone, Copy)]
pub struct VerdictRequestInput<'a> {
    /// The owner's identifier, the verdict's `subject`.
    pub subject: &'a Identifier,
    /// The context the verdict is for.
    pub context_id: &'a str,
    /// The context's validated Sybil policy, whose challenge the request
    /// carries.
    pub policy: ValidatedSybilPolicy<'a>,
    /// The owner's app package name.
    pub package_name: &'a str,
    /// The integrity token string the platform minted over `D`.
    pub token: &'a str,
}

/// Why the owner builds no verdict request, and so sends none.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerdictRequestError {
    /// The policy's challenge is 32 bytes of `0x00`, so no entry can verify.
    #[error("the context's device-attestation challenge is unset")]
    ChallengeUnset,
    /// The token is longer than [`MAX_VERDICT_TOKEN_LEN`] bytes.
    #[error("the integrity token is {len} bytes, more than {MAX_VERDICT_TOKEN_LEN}")]
    TokenTooLong {
        /// The token's length in bytes.
        len: usize,
    },
    /// The body is longer than [`MAX_VERDICT_REQUEST_LEN`] bytes.
    #[error("the verdict request body is {len} bytes, more than {MAX_VERDICT_REQUEST_LEN}")]
    BodyTooLong {
        /// The body's length in bytes.
        len: usize,
    },
    /// The RFC 8785 serialization failed.
    #[error("the verdict request does not serialize: {reason}")]
    Serialization {
        /// The serializer's message.
        reason: String,
    },
}

/// The verdict request's five members, which JCS writes in this order.
#[derive(Serialize)]
struct RequestWire<'a> {
    challenge: String,
    context_id: &'a str,
    package_name: &'a str,
    subject: String,
    token: &'a str,
}

/// A verdict request body (§9.3.1, "The verdict request").
///
/// It is the RFC 8785 serialization of `challenge`, `context_id`,
/// `package_name`, `subject` and `token`, which the owner `POST`s to the
/// verifier entry's URL with `Content-Type: application/json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictRequest {
    body: Vec<u8>,
}

impl VerdictRequest {
    /// The request's `Content-Type`.
    pub const CONTENT_TYPE: &'static str = "application/json";

    /// Builds the request body.
    ///
    /// # Errors
    ///
    /// A [`VerdictRequestError`] for an unset challenge, a token longer than
    /// [`MAX_VERDICT_TOKEN_LEN`] bytes, or a body longer than
    /// [`MAX_VERDICT_REQUEST_LEN`] bytes; the owner then sends nothing.
    pub fn new(input: &VerdictRequestInput<'_>) -> Result<Self, VerdictRequestError> {
        let challenge = set_challenge(input.policy).ok_or(VerdictRequestError::ChallengeUnset)?;
        if input.token.len() > MAX_VERDICT_TOKEN_LEN {
            return Err(VerdictRequestError::TokenTooLong {
                len: input.token.len(),
            });
        }
        let body = crate::jcs::to_vec(&RequestWire {
            challenge: URL_SAFE_NO_PAD.encode(challenge),
            context_id: input.context_id,
            package_name: input.package_name,
            subject: input.subject.to_string(),
            token: input.token,
        })
        .map_err(|reason| VerdictRequestError::Serialization { reason })?;
        if body.len() > MAX_VERDICT_REQUEST_LEN {
            return Err(VerdictRequestError::BodyTooLong { len: body.len() });
        }
        Ok(Self { body })
    }

    /// The body's bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// The verdict response's six members, in JCS order.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseWire {
    cert_digest: String,
    checked_at: u64,
    package_hash: String,
    signature: String,
    token_issued_at: u64,
    verifier: String,
}

/// Why a verifier's answer yields no verdict, and so no entry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerdictResponseError {
    /// `422` with `{"error":"verdict_refused"}`: the verifier refused.
    #[error("the verifier refused the verdict")]
    Refused,
    /// A status other than `200`, or a `422` with any other body.
    #[error("the verifier answered status {status}")]
    UnexpectedStatus {
        /// The HTTP status.
        status: u16,
    },
    /// A `200` body longer than [`MAX_VERDICT_RESPONSE_LEN`] bytes.
    #[error("the verdict response body is {len} bytes, more than {MAX_VERDICT_RESPONSE_LEN}")]
    BodyTooLong {
        /// The body's length in bytes.
        len: usize,
    },
    /// A `200` body that is not one JSON object with exactly the six members,
    /// each once and of its type.
    #[error("the verdict response is not the six-member object: {reason}")]
    Malformed {
        /// The parser's message.
        reason: String,
    },
    /// A `200` body that is not the RFC 8785 serialization of its value.
    #[error("the verdict response is not its canonical RFC 8785 serialization")]
    NotCanonical,
    /// A member's string is not the canonical encoding of a value of its
    /// length.
    #[error("the verdict response's {member} is not canonical")]
    MemberNotCanonical {
        /// The member's name.
        member: &'static str,
    },
}

/// A verdict response a verifier answered `200` with (§9.3.1, "The verdict
/// response"), decoded and checked to be canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictResponse {
    verifier: Identifier,
    package_hash: [u8; 32],
    cert_digest: [u8; 32],
    token_issued_at: u64,
    checked_at: u64,
    signature: [u8; 64],
}

/// Decodes a member's unpadded base64url string of exactly `N` bytes, in its
/// one canonical form (§9.3.1, "Canonical encodings"): the `URL_SAFE_NO_PAD`
/// engine refuses padding, characters outside the alphabet and a last
/// character with nonzero trailing bits, so the one string it decodes to `N`
/// bytes is the canonical one.
fn canonical_base64url<const N: usize>(
    member: &'static str,
    text: &str,
) -> Result<[u8; N], VerdictResponseError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .and_then(|bytes| <[u8; N]>::try_from(bytes).ok())
        .ok_or(VerdictResponseError::MemberNotCanonical { member })
}

impl VerdictResponse {
    /// Reads the verifier's answer from its HTTP status and body.
    ///
    /// # Errors
    ///
    /// A [`VerdictResponseError`] for a refusal, any status but `200`, and a
    /// `200` body that is not the canonical RFC 8785 serialization of the
    /// six-member object.
    pub fn from_http(status: u16, body: &[u8]) -> Result<Self, VerdictResponseError> {
        match status {
            STATUS_OK => {}
            STATUS_REFUSED if body == VERDICT_REFUSED_BODY => {
                return Err(VerdictResponseError::Refused);
            }
            _ => return Err(VerdictResponseError::UnexpectedStatus { status }),
        }
        if body.len() > MAX_VERDICT_RESPONSE_LEN {
            return Err(VerdictResponseError::BodyTooLong { len: body.len() });
        }
        // `deny_unknown_fields` refuses an extra member, and the derived
        // visitor refuses a repeated or missing one.
        let wire: ResponseWire =
            serde_json::from_slice(body).map_err(|error| VerdictResponseError::Malformed {
                reason: error.to_string(),
            })?;
        // The one canonical encoding: re-encode and compare (§9.3.1,
        // "Canonical encodings"). This also refuses whitespace, member order,
        // escapes and number forms JCS does not write, and timestamps past
        // 2^53, which JCS refuses.
        let canonical =
            crate::jcs::to_vec(&wire).map_err(|_| VerdictResponseError::NotCanonical)?;
        if canonical != body {
            return Err(VerdictResponseError::NotCanonical);
        }
        let verifier = wire
            .verifier
            .parse::<Identifier>()
            .map_err(|_| VerdictResponseError::MemberNotCanonical { member: "verifier" })?;
        Ok(Self {
            verifier,
            package_hash: canonical_base64url("package_hash", &wire.package_hash)?,
            cert_digest: canonical_base64url("cert_digest", &wire.cert_digest)?,
            token_issued_at: wire.token_issued_at,
            checked_at: wire.checked_at,
            signature: canonical_base64url("signature", &wire.signature)?,
        })
    }

    /// The verifier's identifier.
    #[must_use]
    pub const fn verifier(&self) -> &Identifier {
        &self.verifier
    }
}

/// The 176-byte verdict (§9.3.1): `verifier ‖ package_hash ‖ cert_digest ‖
/// BE64(token_issued_at) ‖ BE64(checked_at) ‖ signature`.
#[must_use]
pub fn assemble_verdict(response: &VerdictResponse) -> [u8; VERDICT_LEN] {
    let mut verdict = [0u8; VERDICT_LEN];
    let fields: [&[u8]; 6] = [
        response.verifier.as_bytes(),
        &response.package_hash,
        &response.cert_digest,
        &response.token_issued_at.to_be_bytes(),
        &response.checked_at.to_be_bytes(),
        &response.signature,
    ];
    let mut at = 0;
    for field in fields {
        let end = at + field.len();
        if let Some(slot) = verdict.get_mut(at..end) {
            slot.copy_from_slice(field);
        }
        at = end;
    }
    verdict
}

/// What the owner's check of a verdict covers: the same inputs a reader of
/// the owner's entry takes.
#[derive(Debug, Clone, Copy)]
pub struct VerdictCheckInput<'a> {
    /// The owner's identifier, the identifier a reader reads.
    pub subject: &'a Identifier,
    /// The context the entry is for.
    pub context_id: &'a str,
    /// The context's validated Sybil policy.
    pub policy: ValidatedSybilPolicy<'a>,
    /// The integrity token the verdict covers.
    pub token: &'a str,
    /// The assembled verdict.
    pub verdict: &'a [u8; VERDICT_LEN],
    /// The key states the owner resolved for verifiers, each from a
    /// `Confirmed` or `Adopted` resolution.
    pub verifiers: &'a [&'a ResolvedState],
    /// The owner's current time since the Unix epoch.
    pub now: Duration,
}

/// A verdict that passed Play Integrity checks 1 through 6 for the owner's
/// identifier and the context, with the tag and token its entry carries.
///
/// Only [`check_play_integrity_verdict`] builds one, and only on a pass, so
/// [`play_integrity_entry_endpoint`] cannot publish a verdict no check
/// passed. The fields are private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedVerdict {
    tag: [u8; 32],
    token: String,
    verdict: [u8; VERDICT_LEN],
    minted_at: u64,
}

impl CheckedVerdict {
    /// The verdict's `token_issued_at`, which a reader reports as
    /// `minted_at`, Unix seconds.
    #[must_use]
    pub const fn minted_at(&self) -> u64 {
        self.minted_at
    }
}

/// The outcome of the owner's check before it publishes.
///
/// §9.3.1, "What the owner's SDK does": the owner "publishes no entry when
/// the response is not a `200` whose verdict passes Play Integrity checks 1
/// through 6". It is never a `DeviceAttestationVerdict`, so no caller can take
/// it for a read of the owner's record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerdictCheck {
    /// Every check passed; the entry may be published.
    Passed(Box<CheckedVerdict>),
    /// A check failed with this rejection; publish nothing.
    Rejected {
        /// The rejection a reader would return.
        cause: DeviceAttestationRejection,
    },
    /// A check could not run to completion; publish nothing.
    Unverifiable {
        /// The cause a reader would return.
        cause: DeviceAttestationUnverifiable,
    },
}

/// Runs Play Integrity checks 1 through 6 on the owner's verdict.
///
/// `D` is computed for the owner's identifier, the context and the policy's
/// challenge, so the checks run exactly as a reader of the owner's entry runs
/// them. An unset challenge returns `Rejected{ContextChallengeUnset}`, as
/// procedure step 1 does.
///
/// # Errors
///
/// [`CanonicalError`] when `context_id` is longer than `u32::MAX` bytes.
pub fn check_play_integrity_verdict(
    input: &VerdictCheckInput<'_>,
) -> Result<VerdictCheck, CanonicalError> {
    let Some(challenge) = set_challenge(input.policy) else {
        return Ok(VerdictCheck::Rejected {
            cause: DeviceAttestationRejection::ContextChallengeUnset,
        });
    };
    let binding = device_attestation_binding_digest(input.subject, input.context_id, challenge)?;
    let tag = device_attestation_tag(input.subject, input.context_id, challenge)?;
    let read = PlayIntegrityRead {
        token: input.token.as_bytes(),
        verdict: input.verdict,
        binding: &binding,
        policy: input.policy,
        verifiers: input.verifiers,
        now: input.now,
    };
    Ok(match run_play_integrity_checks(&read) {
        Ok(minted_at) => VerdictCheck::Passed(Box::new(CheckedVerdict {
            tag,
            token: input.token.to_owned(),
            verdict: *input.verdict,
            minted_at,
        })),
        Err(PlayIntegrityFailure::Rejected(cause)) => VerdictCheck::Rejected { cause },
        Err(PlayIntegrityFailure::Unverifiable(cause)) => VerdictCheck::Unverifiable { cause },
    })
}

/// A Play Integrity entry's `serviceEndpoint`:
/// `play-integrity.<T>.<token>.<verdict>`, each field unpadded base64url.
#[must_use]
pub fn play_integrity_entry_endpoint(checked: &CheckedVerdict) -> String {
    format!(
        "{PLAY_INTEGRITY_TAG}.{}.{}.{}",
        URL_SAFE_NO_PAD.encode(checked.tag),
        URL_SAFE_NO_PAD.encode(checked.token.as_bytes()),
        URL_SAFE_NO_PAD.encode(checked.verdict),
    )
}

/// What an App Attest entry covers.
#[derive(Debug, Clone, Copy)]
pub struct AppAttestEntryInput<'a> {
    /// The owner's identifier.
    pub subject: &'a Identifier,
    /// The context the entry is for.
    pub context_id: &'a str,
    /// The context's validated Sybil policy, whose challenge `T` covers.
    pub policy: ValidatedSybilPolicy<'a>,
    /// The attestation object the platform adapter returned, in whatever
    /// encoding Apple chose.
    pub attestation_object: &'a [u8],
}

/// Why the owner builds no App Attest entry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AppAttestEntryError {
    /// The policy's challenge is 32 bytes of `0x00`, so no entry can verify.
    #[error("the context's device-attestation challenge is unset")]
    ChallengeUnset,
    /// The attestation object does not re-encode.
    #[error(transparent)]
    Object(#[from] AppAttestObjectError),
    /// `T` does not compute.
    #[error(transparent)]
    Tag(#[from] CanonicalError),
}

/// An App Attest entry's `serviceEndpoint`.
///
/// The string is `app-attest.<T>.<attestation object>`, each field unpadded
/// base64url. The object is re-encoded first by
/// [`canonicalize_app_attest_object`] (§9.3.1, "Canonical encodings"), which
/// drops `receipt` and every key App Attest check 1 does not admit.
///
/// # Errors
///
/// An [`AppAttestEntryError`] for an unset challenge, an object that does not
/// re-encode, or a context id longer than `u32::MAX` bytes.
pub fn app_attest_entry_endpoint(
    input: &AppAttestEntryInput<'_>,
) -> Result<String, AppAttestEntryError> {
    let challenge = set_challenge(input.policy).ok_or(AppAttestEntryError::ChallengeUnset)?;
    let object = canonicalize_app_attest_object(input.attestation_object)?;
    let tag = device_attestation_tag(input.subject, input.context_id, challenge)?;
    Ok(format!(
        "{APP_ATTEST_TAG}.{}.{}",
        URL_SAFE_NO_PAD.encode(tag),
        URL_SAFE_NO_PAD.encode(object),
    ))
}

/// The second by which the owner re-attests for an entry minted at
/// `minted_at`.
///
/// It is `minted_at` plus the policy's `device_attestation_max_age_secs`,
/// saturating at `u64::MAX` (§9.3.1): the last second a reader accepts the
/// entry.
#[must_use]
pub const fn renewal_deadline(policy: &ValidatedSybilPolicy<'_>, minted_at: u64) -> u64 {
    policy.device_attestation_expiry(minted_at)
}

#[cfg(test)]
#[path = "tests/produce.rs"]
mod tests;
