//! Shared identity link attestation construction for FFI bridges.
//!
//! All FFI bridges (`PyO3`, napi-rs, `UniFFI`) create identity link
//! attestations with identical logic: parse verification method, compute the
//! attestation ID, build the unsigned struct, validate structure, and compute
//! canonical signing bytes. This module extracts that shared pipeline so each
//! bridge only needs to handle custody access, signing, and storage — the
//! bridge-specific parts.
//!
//! Gated behind the `resolvers` feature.
//!
//! See spec §3.5.1, §3.5.2.

use std::borrow::Cow;
use std::fmt;

use scp_core::identity::attestation::{
    ATTESTATION_TYPE_IDENTITY_LINK, AttestationClaim, AttestationEvidence, IdentityLinkAttestation,
    VerificationMethod,
};
use scp_core::trust::attestation::RevocationStatus;
use scp_did::DID;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the shared attestation construction pipeline.
///
/// Each bridge converts this to its own error type (e.g. `ScpPyError`,
/// `ScpNapiError`, `ScpError`).
#[derive(Debug)]
pub enum AttestationBuildError {
    /// The verification method string could not be parsed.
    InvalidMethod(String),
    /// The system clock is before the UNIX epoch.
    ClockError,
    /// Structural validation of the attestation failed.
    StructureValidation(String),
    /// Computing canonical signing bytes failed.
    Canonicalization(String),
}

impl fmt::Display for AttestationBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMethod(e) => write!(f, "{e}"),
            Self::ClockError => write!(f, "system clock is before UNIX epoch"),
            Self::StructureValidation(e) => {
                write!(f, "attestation structure validation failed: {e}")
            }
            Self::Canonicalization(e) => write!(f, "attestation signing failed: {e}"),
        }
    }
}

impl std::error::Error for AttestationBuildError {}

// ---------------------------------------------------------------------------
// Builder result
// ---------------------------------------------------------------------------

/// Result of [`build_unsigned_attestation`]: an unsigned attestation and the
/// canonical bytes that must be signed to complete it.
pub struct UnsignedAttestation {
    /// The attestation with an empty `signature` field.
    pub attestation: IdentityLinkAttestation,
    /// The canonical bytes to sign with the identity's active signing key.
    pub canonical_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Shared construction pipeline
// ---------------------------------------------------------------------------

/// Builds an unsigned [`IdentityLinkAttestation`] and computes its canonical
/// signing bytes.
///
/// This is the shared logic across all FFI bridges. After calling this, the
/// bridge must:
/// 1. Sign `canonical_bytes` with the identity's active signing key.
/// 2. Set `attestation.signature` to the signature bytes.
/// 3. Store the attestation in the bridge-specific registry.
///
/// # Arguments
///
/// * `did` — The DID string of the attesting identity.
/// * `platform` — Platform identifier (e.g., `"github.com"`, `"x.com"`).
/// * `handle` — Handle on the platform (e.g., `"@alice"`, `"alice123"`).
/// * `proof` — Method-specific proof data (e.g., OAuth JWT, post URL).
///   Opaque string per §3.5.2 — passed through as-is.
/// * `verification_method` — One of `"oauth"`, `"signed_post"`, `"dns_record"`,
///   `"challenge_response"`.
/// * `platform_id` — Optional platform-specific immutable user ID.
///
/// # Errors
///
/// Returns [`AttestationBuildError`] if the verification method is invalid,
/// the system clock is before the UNIX epoch, structural validation fails,
/// or canonical byte computation fails.
pub fn build_unsigned_attestation(
    did: &str,
    platform: String,
    handle: String,
    proof: String,
    verification_method: &str,
    platform_id: Option<String>,
) -> Result<UnsignedAttestation, AttestationBuildError> {
    let method: VerificationMethod = verification_method
        .parse()
        .map_err(AttestationBuildError::InvalidMethod)?;

    let issuer = DID::from(did);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AttestationBuildError::ClockError)?
        .as_secs();

    let id = IdentityLinkAttestation::compute_id(&issuer, &platform, &handle, now_secs);

    let attestation = IdentityLinkAttestation {
        id,
        attestation_type: Cow::Borrowed(ATTESTATION_TYPE_IDENTITY_LINK),
        issuer: issuer.clone(),
        subject: issuer,
        issued_at: now_secs,
        expires_at: None,
        claim: AttestationClaim::new(platform, handle, platform_id),
        evidence: AttestationEvidence {
            method,
            proof,
            verified_at: now_secs,
            verifier_did: None,
        },
        revocation_status: RevocationStatus::Active,
        signature: Vec::new(),
    };

    // Structural validation before signing.
    let structure_errors = attestation.validate_structure();
    if !structure_errors.is_empty() {
        return Err(AttestationBuildError::StructureValidation(
            structure_errors
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>()
                .join("; "),
        ));
    }

    // Compute canonical bytes for signing.
    let canonical_bytes = attestation
        .canonical_signing_bytes()
        .map_err(|e| AttestationBuildError::Canonicalization(e.to_string()))?;

    Ok(UnsignedAttestation {
        attestation,
        canonical_bytes,
    })
}

// ---------------------------------------------------------------------------
// Shared verification pipeline (spec §3.5.4)
// ---------------------------------------------------------------------------

/// Message every bridge raises from its module-level
/// `identity_verify_link_attestation` free function, alongside
/// [`IDENT_1060`](crate::error_codes::IDENT_1060).
///
/// Spec §3.5.4 step 1 makes resolution of an issuer's DID document a
/// precondition of every later verification step. Phase D (pull request #1695)
/// deleted every process-wide default bridge instance, so a module-level free
/// function reaches no per-instance DID resolver and cannot perform step 1.
/// Verifying a caller-supplied key against a caller-supplied attestation would
/// answer `true` for an attacker who supplies both, which CLAUDE.md's
/// "No dev/test-only stand-ins in production" tenet classifies as a security
/// nullifier — a false guarantee, strictly worse than an honest absence. So
/// each free function fails closed with this message and names its
/// per-instance replacement.
pub const LINK_VERIFY_REQUIRES_INSTANCE: &str = "identity link attestation verification requires a bridge instance: spec §3.5.4 \
     step 1 resolves an issuer's DID document before any signature check, and a \
     module-level free function reaches no DID resolver (phase D, #1695, deleted \
     every process-wide default bridge instance). Call a per-instance method on \
     an `SCP` instance instead: `verify_identity_link_attestation` on PyO3, \
     `identity_verify_link_attestation` on napi-rs and on UniFFI. Verifying \
     against a caller-supplied key would return true for an attacker who supplies \
     both that key and that attestation.";

/// Why [`parse_link_attestation`] rejected a caller's two strings.
///
/// Each bridge maps this to its own error type, all under
/// [`IDENT_1044`](crate::error_codes::IDENT_1044) — a malformed argument, not
/// a verification verdict.
#[derive(Debug)]
pub enum LinkVerifyInputError {
    /// `attestation_json` did not parse as an [`IdentityLinkAttestation`].
    MalformedJson(String),
    /// `issuer_public_key_hex` did not decode as hexadecimal.
    MalformedKeyHex(String),
    /// `issuer_public_key_hex` decoded to a length other than 32 bytes.
    KeyWrongLength(usize),
}

impl fmt::Display for LinkVerifyInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedJson(e) => write!(f, "failed to parse attestation JSON: {e}"),
            Self::MalformedKeyHex(e) => write!(f, "invalid issuer_public_key_hex: {e}"),
            Self::KeyWrongLength(len) => write!(
                f,
                "issuer_public_key_hex must decode to 32 Ed25519 bytes, got {len}"
            ),
        }
    }
}

impl std::error::Error for LinkVerifyInputError {}

/// A caller's two strings, parsed and ready for §3.5.4 verification.
pub struct ParsedLinkAttestation {
    /// Attestation a caller presented.
    pub attestation: IdentityLinkAttestation,
    /// Ed25519 public key a caller names as the one that signed. §3.5.4 step 1
    /// takes a signing key from an issuer's resolved DID document, so this key
    /// is a caller's *assertion about* that document, checked against it — never
    /// a substitute for it.
    pub expected_signing_key: [u8; 32],
}

impl ParsedLinkAttestation {
    /// Returns an issuer DID string a bridge must resolve for §3.5.4 step 1.
    #[must_use]
    pub fn issuer_did(&self) -> &str {
        (*self.attestation.issuer).as_ref()
    }
}

/// Parses a caller's `attestation_json` and `issuer_public_key_hex`.
///
/// # Errors
///
/// Returns [`LinkVerifyInputError`] when either string is malformed, or when a
/// decoded key is not 32 bytes long.
pub fn parse_link_attestation(
    attestation_json: &str,
    issuer_public_key_hex: &str,
) -> Result<ParsedLinkAttestation, LinkVerifyInputError> {
    let attestation: IdentityLinkAttestation = serde_json::from_str(attestation_json)
        .map_err(|e| LinkVerifyInputError::MalformedJson(e.to_string()))?;

    let key_bytes = hex::decode(issuer_public_key_hex)
        .map_err(|e| LinkVerifyInputError::MalformedKeyHex(e.to_string()))?;
    let expected_signing_key: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| LinkVerifyInputError::KeyWrongLength(key_bytes.len()))?;

    Ok(ParsedLinkAttestation {
        attestation,
        expected_signing_key,
    })
}

/// Decides whether an attestation passes spec §3.5.4 against a DID document a
/// bridge resolved for its issuer.
///
/// Delegates every check to the pure, wasm-safe
/// [`verify_identity_link_attestation`](scp_core::identity::attestation::verify_identity_link_attestation)
/// seam, then applies one further rule this boolean surface needs: a key a
/// caller named must be a key that actually verified. A caller that names an
/// `#active` key for an attestation an `#agent` key signed learns `false`,
/// because answering `true` would confirm a claim about a key that signed
/// nothing.
///
/// A Class 2 (Reference) attestation — `signed_post` or `dns_record` — reaches
/// [`ReferenceProofOutcome::NotFetched`], because no bridge fetches a profile
/// page or queries a DNS TXT record. §3.5.0 states that an unverified Reference
/// attestation is equivalent to no attestation, so such an attestation returns
/// `false` here and a caller performs that fetch itself.
///
/// Every rejection reason reaches `tracing` at `info` level, because a boolean
/// return cannot carry one.
#[must_use]
pub fn decide_link_attestation(
    parsed: &ParsedLinkAttestation,
    issuer_document: &scp_did::DidDocument,
    now_secs: u64,
) -> bool {
    use scp_core::identity::attestation::{
        IdentityLinkVerifyInput, ReferenceProofOutcome, verify_identity_link_attestation,
    };

    let verified = match verify_identity_link_attestation(&IdentityLinkVerifyInput {
        attestation: &parsed.attestation,
        issuer_document,
        now_secs,
        reference_proof: ReferenceProofOutcome::NotFetched,
    }) {
        Ok(verified) => verified,
        Err(reason) => {
            tracing::info!(
                attestation_id = %parsed.attestation.id,
                issuer = %parsed.attestation.issuer,
                %reason,
                "identity link attestation rejected (spec §3.5.4)"
            );
            return false;
        }
    };

    if verified.signing_public_key != parsed.expected_signing_key {
        tracing::info!(
            attestation_id = %parsed.attestation.id,
            issuer = %parsed.attestation.issuer,
            verified_fragment = verified.signing_key_fragment,
            "identity link attestation verified under a different verification method \
             than a caller named, so a caller's assertion about which key signed is false"
        );
        return false;
    }

    true
}
