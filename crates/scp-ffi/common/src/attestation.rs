//! Shared identity link attestation construction for FFI bridges.
//!
//! All non-WASM FFI bridges (`PyO3`, napi-rs, `UniFFI`) create identity link
//! attestations with identical logic: parse verification method, compute the
//! attestation ID, build the unsigned struct, validate structure, and compute
//! canonical signing bytes. This module extracts that shared pipeline so each
//! bridge only needs to handle custody access, signing, and storage — the
//! bridge-specific parts.
//!
//! Gated behind the `resolvers` feature (not available for WASM — ADR-034).
//!
//! See spec §3.5.1, §3.5.2.

use std::borrow::Cow;
use std::fmt;

use scp_core::identity::attestation::{
    ATTESTATION_TYPE_IDENTITY_LINK, AttestationClaim, AttestationEvidence, IdentityLinkAttestation,
    VerificationMethod,
};
use scp_core::trust::attestation::RevocationStatus;
use scp_identity::DID;

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
