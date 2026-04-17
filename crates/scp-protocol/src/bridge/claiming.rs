//! Shadow claiming via identity attestation.
//!
//! When an external platform participant wants to transition from a shadow
//! identity to a native SCP identity, they publish an identity attestation
//! (Spec section 3.5) binding their external handle to a DID. The protocol
//! verifies the attestation matches the shadow's platform handle, retires
//! the shadow, and retroattributes historical actions to the claimant DID.
//! Claiming is one-way and irreversible.
//!
//! # Workflow
//!
//! 1. Claimant constructs a [`ClaimRequest`] with their identity attestation.
//! 2. [`claim_shadow`] verifies:
//!    - The shadow exists and is unclaimed.
//!    - The attestation is an `IdentityLink` type.
//!    - The attestation subject matches the claimant DID.
//!    - The platform handle in the attestation claim matches the shadow's handle.
//!    - The attestation is not revoked.
//!    - The Ed25519 signature on the claim request is valid.
//!    - The Ed25519 signature on the identity attestation is valid.
//! 3. On success, the shadow's provenance status transitions from `Shadow` to
//!    `Claimed`. A [`ShadowClaimEvent`] is produced for the context's Merkle log.
//! 4. The claim is irreversible: the shadow cannot be unclaimed or reassigned.
//!
//! # Invariants
//!
//! - **One-way:** Once claimed, a shadow cannot return to `Shadow` status.
//! - **Irreversible:** A claimed shadow cannot be re-assigned to a different DID.
//! - **Handle match:** The attestation's platform handle must exactly match the
//!   shadow's platform handle.
//! - **Signature verification:** Both the claim request and attestation signatures
//!   are cryptographically verified inside `claim_shadow`.
//!
//! See ADR-023 acceptance criteria 7-8 in `.docs/adrs/phase-5.md`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ContextId, DID, ShadowProvenanceStatus};
use crate::crypto::ed25519::verify_ed25519_signature;
use crate::trust::AttestationType;
use crate::trust::attestation::{Attestation, RevocationStatus};
use scp_event_log::Ed25519Signature;

use super::shadow::ShadowRegistry;

// ---------------------------------------------------------------------------
// ClaimError
// ---------------------------------------------------------------------------

/// Errors produced by shadow claiming operations.
///
/// See ADR-023 acceptance criteria 7-8 in `.docs/adrs/phase-5.md`.
#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    /// The platform handle in the attestation does not match the shadow's
    /// platform handle.
    #[error("platform handle mismatch: attestation handle does not match shadow handle")]
    HandleMismatch,

    /// The identity attestation is invalid (wrong type, revoked, or subject
    /// mismatch).
    #[error("identity attestation is invalid: {reason}")]
    AttestationInvalid {
        /// Human-readable reason for invalidity.
        reason: String,
    },

    /// The shadow has already been claimed (bound to a DID).
    #[error("shadow {shadow_id} has already been claimed")]
    AlreadyClaimed {
        /// The shadow ID that was already claimed.
        shadow_id: String,
    },

    /// No shadow with the given ID exists in the registry.
    #[error("shadow not found: {shadow_id}")]
    ShadowNotFound {
        /// The shadow ID that was not found.
        shadow_id: String,
    },

    /// The Ed25519 signature on the claim request is invalid.
    #[error("claim request signature verification failed: {reason}")]
    InvalidClaimSignature {
        /// Human-readable reason for signature invalidity.
        reason: String,
    },

    /// The Ed25519 signature on the identity attestation is invalid.
    #[error("attestation signature verification failed: {reason}")]
    InvalidAttestationSignature {
        /// Human-readable reason for signature invalidity.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// ClaimRequest
// ---------------------------------------------------------------------------

/// A request to claim a shadow identity by binding it to a DID via identity
/// attestation (Spec section 3.5).
///
/// The claimant publishes an identity attestation binding their external
/// platform handle to their DID. The protocol verifies the attestation
/// matches the shadow's platform handle and, on success, retires the shadow
/// and retroattributes historical actions to the claimant DID.
///
/// See ADR-023 acceptance criterion 7.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRequest {
    /// The shadow identity to claim.
    pub shadow_id: String,

    /// DID of the claimant (the external participant transitioning to native
    /// SCP identity).
    pub claimant_did: DID,

    /// The external platform handle the claimant is asserting ownership of.
    pub platform_handle: String,

    /// Identity attestation (Spec section 3.5) binding the external handle
    /// to the claimant DID.
    pub identity_attestation: Attestation,

    /// Unix timestamp (seconds) when the claim request was created.
    pub timestamp: u64,

    /// Ed25519 signature over the claim request content.
    #[serde(with = "serde_bytes")]
    pub signature: Ed25519Signature,
}

// ---------------------------------------------------------------------------
// ShadowClaimEvent
// ---------------------------------------------------------------------------

/// A context event recording the claiming of a shadow identity.
///
/// This event is appended to the context's Merkle log (ADR-011) to provide
/// an auditable, immutable record of the claim. Once recorded, the claim
/// cannot be reversed.
///
/// See ADR-023 acceptance criterion 7: "Claiming is a context event in the
/// Merkle log."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowClaimEvent {
    /// The shadow identity that was claimed.
    pub shadow_id: String,

    /// The DID the shadow is now bound to.
    pub claimant_did: DID,

    /// The external platform handle that was verified.
    pub platform_handle: String,

    /// The attestation ID used to verify the claim.
    pub attestation_id: String,

    /// The context in which this claim occurred.
    pub context_id: ContextId,

    /// Unix timestamp (seconds) when the claim was processed.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Signature verification helpers
// ---------------------------------------------------------------------------

use scp_primitives::extract_public_key_from_did;

/// Computes the canonical SHA-256 hash of a claim request's content
/// (excluding the signature field).
///
/// ```text
/// SHA-256("SCP-CLAIM-V1:" || len(shadow_id) || shadow_id
///         || len(claimant_did) || claimant_did
///         || len(platform_handle) || platform_handle
///         || len(attestation_id) || attestation_id || timestamp_BE)
/// ```
///
/// Variable-length fields are prefixed with their length as a 4-byte
/// big-endian u32 to prevent field boundary ambiguity. The domain separator
/// prevents cross-protocol hash confusion.
fn compute_claim_canonical_hash(request: &ClaimRequest) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-CLAIM-V1:");
    // Length-prefix closure for variable-length fields. Field values (DIDs,
    // handles, IDs) are short strings; truncation is not a concern.
    #[allow(clippy::cast_possible_truncation)]
    let length_prefix = |hasher: &mut Sha256, bytes: &[u8]| {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    };
    length_prefix(&mut hasher, request.shadow_id.as_bytes());
    length_prefix(&mut hasher, request.claimant_did.as_bytes());
    length_prefix(&mut hasher, request.platform_handle.as_bytes());
    length_prefix(&mut hasher, request.identity_attestation.id.as_bytes());
    hasher.update(request.timestamp.to_be_bytes()); // fixed-width, no prefix needed
    hasher.finalize().to_vec()
}

/// Verifies the Ed25519 signature on a [`ClaimRequest`].
///
/// Extracts the public key from `request.claimant_did`, computes the
/// canonical hash of the request content, and verifies `request.signature`.
fn verify_claim_signature(request: &ClaimRequest) -> Result<(), ClaimError> {
    let public_key_bytes = extract_public_key_from_did(&request.claimant_did)
        .map_err(|reason| ClaimError::InvalidClaimSignature { reason })?;
    let canonical_hash = compute_claim_canonical_hash(request);
    verify_ed25519_signature(&public_key_bytes, &canonical_hash, &request.signature)
        .map_err(|reason| ClaimError::InvalidClaimSignature { reason })
}

/// Verifies the Ed25519 signature on an [`Attestation`].
///
/// Extracts the public key from `attestation.issuer`, computes the
/// canonical hash of the attestation content, and verifies
/// `attestation.signature`.
fn verify_attestation_signature(attestation: &Attestation) -> Result<(), ClaimError> {
    let public_key_bytes = extract_public_key_from_did(&attestation.issuer)
        .map_err(|reason| ClaimError::InvalidAttestationSignature { reason })?;
    let canonical_bytes = crate::trust::attestation::canonical_attestation_bytes(attestation)
        .map_err(|e| ClaimError::InvalidAttestationSignature {
            reason: e.to_string(),
        })?;
    verify_ed25519_signature(&public_key_bytes, &canonical_bytes, &attestation.signature)
        .map_err(|reason| ClaimError::InvalidAttestationSignature { reason })
}

// ---------------------------------------------------------------------------
// validate_claim_request
// ---------------------------------------------------------------------------

/// Validates a claim request's attestation fields and cryptographic signatures.
///
/// Checks (in order):
/// 1. Attestation type is `IdentityLink`.
/// 2. Attestation subject matches the claimant DID.
/// 3. Attestation is not revoked.
/// 4. Attestation `platform_handle` claim matches the shadow's handle.
/// 5. Attestation Ed25519 signature is valid.
/// 6. Claim request Ed25519 signature is valid.
fn validate_claim_request(
    request: &ClaimRequest,
    shadow_platform_handle: &str,
) -> Result<(), ClaimError> {
    // 3. Validate the attestation type is IdentityLink.
    if request.identity_attestation.attestation_type != AttestationType::IdentityLink {
        return Err(ClaimError::AttestationInvalid {
            reason: format!(
                "expected IdentityLink attestation, got {:?}",
                request.identity_attestation.attestation_type
            ),
        });
    }

    // 4. Validate the attestation subject matches the claimant DID.
    if request.identity_attestation.subject != request.claimant_did {
        return Err(ClaimError::AttestationInvalid {
            reason: format!(
                "attestation subject {} does not match claimant DID {}",
                request.identity_attestation.subject, request.claimant_did
            ),
        });
    }

    // 5. Validate the attestation is not revoked.
    // Per §7.4.1, only the issuer can revoke their own attestation.
    if let RevocationStatus::Revoked { revoked_by, .. } =
        &request.identity_attestation.revocation_status
    {
        if *revoked_by != request.identity_attestation.issuer {
            return Err(ClaimError::AttestationInvalid {
                reason: format!(
                    "attestation revoked_by {} does not match issuer {}",
                    revoked_by, request.identity_attestation.issuer,
                ),
            });
        }
        return Err(ClaimError::AttestationInvalid {
            reason: "attestation has been revoked".to_owned(),
        });
    }

    // 6. Verify platform handle match.
    let attestation_handle = request
        .identity_attestation
        .claim
        .get("platform_handle")
        .and_then(serde_json::Value::as_str);

    match attestation_handle {
        Some(handle) if handle == shadow_platform_handle => {}
        Some(_) => return Err(ClaimError::HandleMismatch),
        None => {
            return Err(ClaimError::AttestationInvalid {
                reason: "attestation claim missing 'platform_handle' field".to_owned(),
            });
        }
    }

    // 7. Verify the Ed25519 signature on the identity attestation.
    verify_attestation_signature(&request.identity_attestation)?;

    // 8. Verify the Ed25519 signature on the claim request.
    verify_claim_signature(request)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// claim_shadow
// ---------------------------------------------------------------------------

/// Claims a shadow identity by verifying an identity attestation and binding
/// the shadow to a DID.
///
/// This function implements the full shadow claiming workflow (ADR-023
/// acceptance criteria 7-8):
///
/// 1. Verifies the shadow exists and is unclaimed.
/// 2. Validates the identity attestation:
///    - Must be an `IdentityLink` attestation type.
///    - The attestation subject must match the claimant DID.
///    - The attestation must not be revoked.
/// 3. Verifies the platform handle in the attestation matches the shadow's
///    platform handle.
/// 4. Cryptographically verifies the Ed25519 signature on the attestation.
/// 5. Cryptographically verifies the Ed25519 signature on the claim request.
/// 6. Transitions the shadow's provenance status from `Shadow` to `Claimed`.
/// 7. Produces a [`ShadowClaimEvent`] for the context's Merkle log.
///
/// # Arguments
///
/// - `registry` -- The shadow registry for this context.
/// - `request` -- The claim request containing the attestation and claimant
///   details.
///
/// # One-way and irreversible
///
/// Once this function succeeds, the shadow is permanently bound to the
/// claimant DID. There is no `unclaim_shadow` function. The shadow cannot
/// be re-assigned to a different DID (attempting to claim an already-claimed
/// shadow returns [`ClaimError::AlreadyClaimed`]).
///
/// # Errors
///
/// Returns [`ClaimError::ShadowNotFound`] if no shadow with the given ID
/// exists.
///
/// Returns [`ClaimError::AlreadyClaimed`] if the shadow has already been
/// claimed.
///
/// Returns [`ClaimError::AttestationInvalid`] if the attestation is not an
/// `IdentityLink` type, the subject does not match the claimant DID, or
/// the attestation is revoked.
///
/// Returns [`ClaimError::HandleMismatch`] if the platform handle in the
/// attestation does not match the shadow's platform handle.
///
/// Returns [`ClaimError::InvalidAttestationSignature`] if the attestation's
/// Ed25519 signature is invalid.
///
/// Returns [`ClaimError::InvalidClaimSignature`] if the claim request's
/// Ed25519 signature is invalid.
///
/// See ADR-023 acceptance criteria 7-8.
pub fn claim_shadow(
    registry: &mut ShadowRegistry,
    request: &ClaimRequest,
) -> Result<ShadowClaimEvent, ClaimError> {
    // 1. Verify the shadow exists.
    let Ok(shadow) = registry.find_shadow_mut(&request.shadow_id) else {
        return Err(ClaimError::ShadowNotFound {
            shadow_id: request.shadow_id.clone(),
        });
    };

    // 2. Verify the shadow is unclaimed (one-way: cannot re-claim).
    if shadow.provenance_status == ShadowProvenanceStatus::Claimed {
        return Err(ClaimError::AlreadyClaimed {
            shadow_id: request.shadow_id.clone(),
        });
    }

    // 3-8. Validate attestation, handle match, and signatures.
    validate_claim_request(request, &shadow.platform_handle)?;

    // 9. All verifications passed. Retire the shadow by transitioning its
    //    provenance status to Claimed. This is irreversible.
    shadow.provenance_status = ShadowProvenanceStatus::Claimed;

    // 10. Produce a ShadowClaimEvent for the Merkle log.
    Ok(ShadowClaimEvent {
        shadow_id: request.shadow_id.clone(),
        claimant_did: request.claimant_did.clone(),
        platform_handle: request.platform_handle.clone(),
        attestation_id: request.identity_attestation.id.clone(),
        context_id: registry.context_id().to_owned(),
        timestamp: request.timestamp,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::single_char_pattern,
    clippy::similar_names
)]
mod tests {
    use std::time::Duration;

    use ed25519_dalek::Signer;

    use super::*;
    use crate::bridge::shadow::{CreateShadowParams, ShadowRegistry, create_shadow};
    use crate::bridge::{BridgeMode, ShadowProvenanceStatus};
    use crate::crypto::sender_keys::SenderKeyStore;
    use crate::trust::attestation::AttestationEvidence;

    // -------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------

    const CTX: &str = "ctx-claim-test";
    const BRIDGE_ID: &str = "bridge-claim-001";
    const SHADOW_ID: &str = "shadow-claim-001";
    const HANDLE: &str = "@alice#1234";
    const ATTESTATION_ID: &str = "attest-claim-001";

    // -------------------------------------------------------------------
    // Crypto helpers (imported from shared test helpers)
    // -------------------------------------------------------------------

    use scp_event_log::test_helpers::{did_from_pubkey, test_keypair};

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    fn make_registry() -> ShadowRegistry {
        ShadowRegistry::new(CTX.to_owned())
    }

    fn create_test_shadow(registry: &mut ShadowRegistry) {
        let params = CreateShadowParams {
            shadow_id: SHADOW_ID,
            bridge_id: BRIDGE_ID,
            bridge_mode: BridgeMode::Relay,
            platform_handle: HANDLE,
            context_member_dids: &[],
            timestamp: 1_700_000_100,
        };
        create_shadow(registry, &mut SenderKeyStore::new(), &params).unwrap();
    }

    fn make_identity_attestation(
        subject_did: &str,
        platform_handle: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Attestation {
        let mut attestation = Attestation {
            id: ATTESTATION_ID.to_owned(),
            attestation_type: AttestationType::IdentityLink,
            issuer: subject_did.into(),
            subject: subject_did.into(),
            claim: serde_json::json!({
                "platform_handle": platform_handle,
                "platform": "discord"
            }),
            evidence: Some(AttestationEvidence {
                evidence_type: "signed-challenge".to_owned(),
                data: serde_json::json!({"challenge": "abc123"}),
            }),
            issued_at: 1_700_000_200,
            expires_at: Some(1_700_100_000),
            renewal_interval: Some(Duration::from_hours(24)),
            revocation_status: RevocationStatus::Active,
            signature: Vec::new(),
            renewed_at: None,
        };

        // Sign the attestation with the issuer's key using the canonical
        // bytes from the trust module (the single source of truth).
        let canonical_bytes =
            crate::trust::attestation::canonical_attestation_bytes(&attestation).unwrap();
        let sig = signing_key.sign(&canonical_bytes);
        attestation.signature = sig.to_bytes().to_vec();

        attestation
    }

    fn make_claim_request(
        shadow_id: &str,
        claimant_did: &str,
        platform_handle: &str,
        attestation: Attestation,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> ClaimRequest {
        let mut request = ClaimRequest {
            shadow_id: shadow_id.to_owned(),
            claimant_did: claimant_did.into(),
            platform_handle: platform_handle.to_owned(),
            identity_attestation: attestation,
            timestamp: 1_700_000_300,
            signature: Vec::new(),
        };

        // Sign the claim request with the claimant's key.
        let canonical_hash = compute_claim_canonical_hash(&request);
        let sig = signing_key.sign(&canonical_hash);
        request.signature = sig.to_bytes().to_vec();

        request
    }

    fn make_default_claim_request() -> ClaimRequest {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let attestation = make_identity_attestation(&did, HANDLE, &signing_key);
        make_claim_request(SHADOW_ID, &did, HANDLE, attestation, &signing_key)
    }

    // -------------------------------------------------------------------
    // Successful claiming
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_succeeds_with_valid_attestation() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let request = make_default_claim_request();
        let result = claim_shadow(&mut registry, &request);

        assert!(result.is_ok());
    }

    #[test]
    fn claim_shadow_success_returns_correct_ids() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let attestation = make_identity_attestation(&did, HANDLE, &signing_key);
        let request = make_claim_request(SHADOW_ID, &did, HANDLE, attestation, &signing_key);
        let event = claim_shadow(&mut registry, &request).unwrap();

        assert_eq!(event.shadow_id, SHADOW_ID);
        assert_eq!(event.claimant_did, did);
    }

    #[test]
    fn claim_shadow_transitions_provenance_to_claimed() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        // Before claiming: status is Shadow.
        assert_eq!(
            registry.shadows()[0].provenance_status,
            ShadowProvenanceStatus::Shadow
        );

        let request = make_default_claim_request();
        let result = claim_shadow(&mut registry, &request);
        assert!(result.is_ok());

        // After claiming: status is Claimed.
        assert_eq!(
            registry.shadows()[0].provenance_status,
            ShadowProvenanceStatus::Claimed
        );
    }

    #[test]
    fn claim_shadow_produces_event_with_correct_fields() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let attestation = make_identity_attestation(&did, HANDLE, &signing_key);
        let request = make_claim_request(SHADOW_ID, &did, HANDLE, attestation, &signing_key);
        let event = claim_shadow(&mut registry, &request).unwrap();
        assert_eq!(event.shadow_id, SHADOW_ID);
        assert_eq!(event.claimant_did, did);
        assert_eq!(event.platform_handle, HANDLE);
        assert_eq!(event.attestation_id, ATTESTATION_ID);
        assert_eq!(event.context_id, CTX);
        assert_eq!(event.timestamp, 1_700_000_300);
    }

    // -------------------------------------------------------------------
    // ShadowNotFound
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_fails_when_shadow_not_found() {
        let mut registry = make_registry();
        // No shadows created.

        let request = make_default_claim_request();
        let err = claim_shadow(&mut registry, &request).unwrap_err();

        assert!(matches!(err, ClaimError::ShadowNotFound { .. }));
    }

    #[test]
    fn claim_shadow_fails_for_wrong_shadow_id() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let attestation = make_identity_attestation(&did, HANDLE, &signing_key);
        let request = make_claim_request(
            "nonexistent-shadow",
            &did,
            HANDLE,
            attestation,
            &signing_key,
        );
        let err = claim_shadow(&mut registry, &request).unwrap_err();

        assert!(matches!(err, ClaimError::ShadowNotFound { .. }));
    }

    // -------------------------------------------------------------------
    // AlreadyClaimed (one-way, irreversible)
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_fails_when_already_claimed() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        // First claim succeeds.
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let attestation = make_identity_attestation(&did, HANDLE, &signing_key);
        let request = make_claim_request(SHADOW_ID, &did, HANDLE, attestation, &signing_key);
        assert!(claim_shadow(&mut registry, &request).is_ok());

        // Second claim fails with AlreadyClaimed.
        let attestation2 = make_identity_attestation(&did, HANDLE, &signing_key);
        let request2 = make_claim_request(SHADOW_ID, &did, HANDLE, attestation2, &signing_key);
        let err = claim_shadow(&mut registry, &request2).unwrap_err();
        assert!(matches!(err, ClaimError::AlreadyClaimed { .. }));
    }

    #[test]
    fn claimed_shadow_cannot_be_reassigned_to_different_did() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        // First claim by Alice.
        let (alice_vk, alice_sk) = test_keypair();
        let alice_did = did_from_pubkey(&alice_vk);
        let attestation = make_identity_attestation(&alice_did, HANDLE, &alice_sk);
        let request = make_claim_request(SHADOW_ID, &alice_did, HANDLE, attestation, &alice_sk);
        assert!(claim_shadow(&mut registry, &request).is_ok());

        // Attempt to re-claim by Bob.
        let (bob_vk, bob_sk) = test_keypair();
        let bob_did = did_from_pubkey(&bob_vk);
        let attestation = make_identity_attestation(&bob_did, HANDLE, &bob_sk);
        let bob_request = make_claim_request(SHADOW_ID, &bob_did, HANDLE, attestation, &bob_sk);
        let err = claim_shadow(&mut registry, &bob_request).unwrap_err();
        assert!(matches!(err, ClaimError::AlreadyClaimed { .. }));
    }

    // -------------------------------------------------------------------
    // HandleMismatch
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_fails_on_handle_mismatch() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        // Attestation has a different handle than the shadow.
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let attestation = make_identity_attestation(&did, "@wrong_handle", &signing_key);
        let request =
            make_claim_request(SHADOW_ID, &did, "@wrong_handle", attestation, &signing_key);
        let err = claim_shadow(&mut registry, &request).unwrap_err();

        assert!(matches!(err, ClaimError::HandleMismatch));
    }

    // -------------------------------------------------------------------
    // AttestationInvalid -- wrong type
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_fails_for_non_identity_link_attestation() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let mut attestation = make_identity_attestation(&did, HANDLE, &signing_key);
        attestation.attestation_type = AttestationType::Endorsement;

        let request = make_claim_request(SHADOW_ID, &did, HANDLE, attestation, &signing_key);
        let err = claim_shadow(&mut registry, &request).unwrap_err();

        assert!(matches!(err, ClaimError::AttestationInvalid { .. }));
    }

    #[test]
    fn claim_shadow_fails_for_capability_delegation_attestation() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let mut attestation = make_identity_attestation(&did, HANDLE, &signing_key);
        attestation.attestation_type = AttestationType::CapabilityDelegation;

        let request = make_claim_request(SHADOW_ID, &did, HANDLE, attestation, &signing_key);
        let err = claim_shadow(&mut registry, &request).unwrap_err();

        assert!(matches!(err, ClaimError::AttestationInvalid { .. }));
    }

    // -------------------------------------------------------------------
    // AttestationInvalid -- subject mismatch
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_fails_when_attestation_subject_does_not_match_claimant() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        // Attestation subject is for a different DID.
        let (other_vk, other_sk) = test_keypair();
        let other_did = did_from_pubkey(&other_vk);
        let (claimant_vk, claimant_sk) = test_keypair();
        let claimant_did = did_from_pubkey(&claimant_vk);

        let attestation = make_identity_attestation(&other_did, HANDLE, &other_sk);
        let request =
            make_claim_request(SHADOW_ID, &claimant_did, HANDLE, attestation, &claimant_sk);
        let err = claim_shadow(&mut registry, &request).unwrap_err();

        assert!(matches!(err, ClaimError::AttestationInvalid { .. }));
    }

    // -------------------------------------------------------------------
    // AttestationInvalid -- revoked
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_fails_when_attestation_is_revoked() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let mut attestation = make_identity_attestation(&did, HANDLE, &signing_key);
        attestation.revocation_status = RevocationStatus::Revoked {
            revoked_at: 1_700_000_250,
            reason: "compromised".to_owned(),
            revoked_by: did.clone(),
        };

        let request = make_claim_request(SHADOW_ID, &did, HANDLE, attestation, &signing_key);
        let err = claim_shadow(&mut registry, &request).unwrap_err();

        assert!(matches!(err, ClaimError::AttestationInvalid { .. }));
    }

    #[test]
    fn claim_shadow_fails_when_revoked_by_non_issuer() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let mut attestation = make_identity_attestation(&did, HANDLE, &signing_key);
        attestation.revocation_status = RevocationStatus::Revoked {
            revoked_at: 1_700_000_250,
            reason: "forged revocation".to_owned(),
            revoked_by: "did:key:mallory".into(),
        };

        let request = make_claim_request(SHADOW_ID, &did, HANDLE, attestation, &signing_key);
        let err = claim_shadow(&mut registry, &request).unwrap_err();

        match &err {
            ClaimError::AttestationInvalid { reason } => {
                assert!(
                    reason.contains("revoked_by"),
                    "expected revoked_by mismatch error, got: {reason}",
                );
            }
            other => panic!("expected AttestationInvalid, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // AttestationInvalid -- missing platform_handle in claim
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_fails_when_attestation_claim_missing_platform_handle() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let mut attestation = make_identity_attestation(&did, HANDLE, &signing_key);
        attestation.claim = serde_json::json!({"platform": "discord"});

        let request = make_claim_request(SHADOW_ID, &did, HANDLE, attestation, &signing_key);
        let err = claim_shadow(&mut registry, &request).unwrap_err();

        assert!(matches!(err, ClaimError::AttestationInvalid { .. }));
    }

    // -------------------------------------------------------------------
    // Signature verification -- bad claim request signature
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_fails_with_invalid_claim_request_signature() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let attestation = make_identity_attestation(&did, HANDLE, &signing_key);
        let mut request = make_claim_request(SHADOW_ID, &did, HANDLE, attestation, &signing_key);

        // Corrupt the claim request signature.
        request.signature = vec![0u8; 64];

        let err = claim_shadow(&mut registry, &request).unwrap_err();

        assert!(
            matches!(err, ClaimError::InvalidClaimSignature { .. }),
            "expected InvalidClaimSignature, got: {err}"
        );
    }

    // -------------------------------------------------------------------
    // Signature verification -- bad attestation signature
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_fails_with_invalid_attestation_signature() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let mut attestation = make_identity_attestation(&did, HANDLE, &signing_key);

        // Corrupt the attestation signature.
        attestation.signature = vec![0u8; 64];

        // Re-sign the claim request (so only the attestation sig is bad).
        let request = make_claim_request(SHADOW_ID, &did, HANDLE, attestation, &signing_key);

        let err = claim_shadow(&mut registry, &request).unwrap_err();

        assert!(
            matches!(err, ClaimError::InvalidAttestationSignature { .. }),
            "expected InvalidAttestationSignature, got: {err}"
        );
    }

    // -------------------------------------------------------------------
    // Signature verification -- wrong key for claim request
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_fails_when_claim_signed_by_wrong_key() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let attestation = make_identity_attestation(&did, HANDLE, &signing_key);

        // Sign the claim request with a different key.
        let (_wrong_vk, wrong_sk) = test_keypair();
        let mut request = make_claim_request(SHADOW_ID, &did, HANDLE, attestation, &signing_key);

        // Override the signature with one from the wrong key.
        let canonical_hash = compute_claim_canonical_hash(&request);
        let wrong_sig = wrong_sk.sign(&canonical_hash);
        request.signature = wrong_sig.to_bytes().to_vec();

        let err = claim_shadow(&mut registry, &request).unwrap_err();

        assert!(
            matches!(err, ClaimError::InvalidClaimSignature { .. }),
            "expected InvalidClaimSignature for wrong-key signature"
        );
    }

    // -------------------------------------------------------------------
    // Serialization roundtrips
    // -------------------------------------------------------------------

    #[test]
    fn claim_request_serialization_roundtrip() {
        let request = make_default_claim_request();

        let json = serde_json::to_string(&request);
        assert!(json.is_ok(), "serialization should succeed");

        let deserialized: Result<ClaimRequest, _> =
            serde_json::from_str(json.as_ref().map_or("", String::as_str));
        assert!(deserialized.is_ok(), "deserialization should succeed");

        let restored = deserialized.unwrap();
        assert_eq!(restored.shadow_id, request.shadow_id);
        assert_eq!(restored.claimant_did, request.claimant_did);
        assert_eq!(restored.platform_handle, request.platform_handle);
        assert_eq!(restored.timestamp, request.timestamp);
        assert_eq!(
            restored.identity_attestation.id,
            request.identity_attestation.id
        );
    }

    #[test]
    fn shadow_claim_event_serialization_roundtrip() {
        let event = ShadowClaimEvent {
            shadow_id: SHADOW_ID.to_owned(),
            claimant_did: "did:test:roundtrip".into(),
            platform_handle: HANDLE.to_owned(),
            attestation_id: ATTESTATION_ID.to_owned(),
            context_id: CTX.to_owned(),
            timestamp: 1_700_000_300,
        };

        let json = serde_json::to_string(&event);
        assert!(json.is_ok(), "serialization should succeed");

        let deserialized: Result<ShadowClaimEvent, _> =
            serde_json::from_str(json.as_ref().map_or("", String::as_str));
        assert!(deserialized.is_ok(), "deserialization should succeed");

        let restored = deserialized.unwrap();
        assert_eq!(restored.shadow_id, event.shadow_id);
        assert_eq!(restored.claimant_did, event.claimant_did);
        assert_eq!(restored.platform_handle, event.platform_handle);
        assert_eq!(restored.attestation_id, event.attestation_id);
        assert_eq!(restored.context_id, event.context_id);
        assert_eq!(restored.timestamp, event.timestamp);
    }

    // -------------------------------------------------------------------
    // Multiple shadows -- claiming one does not affect others
    // -------------------------------------------------------------------

    #[test]
    fn claiming_one_shadow_does_not_affect_other_shadows() {
        let mut registry = make_registry();

        // Create two shadows.
        let params_a = CreateShadowParams {
            shadow_id: "shadow-a",
            bridge_id: BRIDGE_ID,
            bridge_mode: BridgeMode::Relay,
            platform_handle: "@alice",
            context_member_dids: &[],
            timestamp: 1_700_000_100,
        };
        create_shadow(&mut registry, &mut SenderKeyStore::new(), &params_a).unwrap();

        let params_b = CreateShadowParams {
            shadow_id: "shadow-b",
            bridge_id: BRIDGE_ID,
            bridge_mode: BridgeMode::Relay,
            platform_handle: "@bob",
            context_member_dids: &[],
            timestamp: 1_700_000_100,
        };
        create_shadow(&mut registry, &mut SenderKeyStore::new(), &params_b).unwrap();

        // Claim shadow-a.
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let attestation = make_identity_attestation(&did, "@alice", &signing_key);
        let request = make_claim_request("shadow-a", &did, "@alice", attestation, &signing_key);
        assert!(claim_shadow(&mut registry, &request).is_ok());

        // shadow-a is Claimed.
        assert_eq!(
            registry.shadows()[0].provenance_status,
            ShadowProvenanceStatus::Claimed
        );

        // shadow-b is still Shadow.
        assert_eq!(
            registry.shadows()[1].provenance_status,
            ShadowProvenanceStatus::Shadow
        );
    }

    // -------------------------------------------------------------------
    // Event carries context_id from registry
    // -------------------------------------------------------------------

    #[test]
    fn claim_event_carries_registry_context_id() {
        let custom_ctx = "ctx-custom-claim";
        let mut registry = ShadowRegistry::new(custom_ctx.to_owned());
        let params = CreateShadowParams {
            shadow_id: SHADOW_ID,
            bridge_id: BRIDGE_ID,
            bridge_mode: BridgeMode::Puppet,
            platform_handle: HANDLE,
            context_member_dids: &[],
            timestamp: 1_700_000_100,
        };
        create_shadow(&mut registry, &mut SenderKeyStore::new(), &params).unwrap();

        let request = make_default_claim_request();
        let event = claim_shadow(&mut registry, &request).unwrap();

        assert_eq!(event.context_id, custom_ctx);
    }

    // -------------------------------------------------------------------
    // ClaimError Display implementations
    // -------------------------------------------------------------------

    #[test]
    fn claim_error_display_handle_mismatch() {
        let err = ClaimError::HandleMismatch;
        let msg = format!("{err}");
        assert!(msg.contains("mismatch"));
    }

    #[test]
    fn claim_error_display_attestation_invalid() {
        let err = ClaimError::AttestationInvalid {
            reason: "wrong type".to_owned(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("wrong type"));
    }

    #[test]
    fn claim_error_display_already_claimed() {
        let err = ClaimError::AlreadyClaimed {
            shadow_id: "s-001".to_owned(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("s-001"));
        assert!(msg.contains("already been claimed"));
    }

    #[test]
    fn claim_error_display_shadow_not_found() {
        let err = ClaimError::ShadowNotFound {
            shadow_id: "s-404".to_owned(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("s-404"));
    }

    #[test]
    fn claim_error_display_invalid_claim_signature() {
        let err = ClaimError::InvalidClaimSignature {
            reason: "bad sig".to_owned(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("claim request signature verification failed"));
        assert!(msg.contains("bad sig"));
    }

    #[test]
    fn claim_error_display_invalid_attestation_signature() {
        let err = ClaimError::InvalidAttestationSignature {
            reason: "bad attest sig".to_owned(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("attestation signature verification failed"));
        assert!(msg.contains("bad attest sig"));
    }
}
