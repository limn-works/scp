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
//!
//! See ADR-023 acceptance criteria 7-8 in `.docs/adrs/phase-5.md`.

use serde::{Deserialize, Serialize};

use super::{ContextId, DID, ShadowProvenanceStatus};
use crate::event_log::Ed25519Signature;
use crate::trust::attestation::{Attestation, RevocationStatus};
use crate::trust::AttestationType;

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
// ClaimResult
// ---------------------------------------------------------------------------

/// Result of a shadow claiming operation.
///
/// See ADR-023 acceptance criteria 7-8.
#[derive(Debug)]
pub enum ClaimResult {
    /// The shadow was successfully claimed and bound to the claimant DID.
    Success {
        /// The shadow identity that was claimed.
        shadow_id: String,
        /// The DID the shadow is now bound to.
        claimant_did: DID,
    },

    /// The claiming operation failed.
    Failed {
        /// The reason for failure.
        reason: ClaimError,
    },
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
/// 4. Transitions the shadow's provenance status from `Shadow` to `Claimed`.
/// 5. Produces a [`ShadowClaimEvent`] for the context's Merkle log.
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
/// # SAFETY: Callers must verify the Ed25519 signature
///
/// This function does **not** cryptographically verify the `signature` field
/// on the [`ClaimRequest`] or the `signature` on the [`Attestation`]. The
/// caller is responsible for verifying:
///
/// 1. The `ClaimRequest.signature` is a valid Ed25519 signature from the
///    claimant DID over the request content.
/// 2. The `Attestation.signature` is valid (e.g., via
///    [`verify_attestation`](crate::trust::verify_attestation)).
///
/// This separation follows the same pattern as [`upgrade_shadow_role`] in
/// `shadow.rs`, which documents that callers must verify governance
/// authorization.
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
/// See ADR-023 acceptance criteria 7-8.
pub fn claim_shadow(
    registry: &mut ShadowRegistry,
    request: &ClaimRequest,
) -> (ClaimResult, Option<ShadowClaimEvent>) {
    // 1. Verify the shadow exists.
    let shadow = match registry.find_shadow_mut(&request.shadow_id) {
        Ok(s) => s,
        Err(_) => {
            return (
                ClaimResult::Failed {
                    reason: ClaimError::ShadowNotFound {
                        shadow_id: request.shadow_id.clone(),
                    },
                },
                None,
            );
        }
    };

    // 2. Verify the shadow is unclaimed (one-way: cannot re-claim).
    if shadow.provenance_status == ShadowProvenanceStatus::Claimed {
        return (
            ClaimResult::Failed {
                reason: ClaimError::AlreadyClaimed {
                    shadow_id: request.shadow_id.clone(),
                },
            },
            None,
        );
    }

    // 3. Validate the attestation type is IdentityLink.
    if request.identity_attestation.attestation_type != AttestationType::IdentityLink {
        return (
            ClaimResult::Failed {
                reason: ClaimError::AttestationInvalid {
                    reason: format!(
                        "expected IdentityLink attestation, got {:?}",
                        request.identity_attestation.attestation_type
                    ),
                },
            },
            None,
        );
    }

    // 4. Validate the attestation subject matches the claimant DID.
    if request.identity_attestation.subject != request.claimant_did {
        return (
            ClaimResult::Failed {
                reason: ClaimError::AttestationInvalid {
                    reason: format!(
                        "attestation subject {} does not match claimant DID {}",
                        request.identity_attestation.subject, request.claimant_did
                    ),
                },
            },
            None,
        );
    }

    // 5. Validate the attestation is not revoked.
    if let RevocationStatus::Revoked { .. } = &request.identity_attestation.revocation_status {
        return (
            ClaimResult::Failed {
                reason: ClaimError::AttestationInvalid {
                    reason: "attestation has been revoked".to_owned(),
                },
            },
            None,
        );
    }

    // 6. Extract the platform handle from the attestation claim and verify
    //    it matches the shadow's platform handle.
    let attestation_handle = request
        .identity_attestation
        .claim
        .get("platform_handle")
        .and_then(serde_json::Value::as_str);

    match attestation_handle {
        Some(handle) if handle == shadow.platform_handle => {
            // Handle matches -- proceed.
        }
        Some(_) => {
            return (
                ClaimResult::Failed {
                    reason: ClaimError::HandleMismatch,
                },
                None,
            );
        }
        None => {
            return (
                ClaimResult::Failed {
                    reason: ClaimError::AttestationInvalid {
                        reason: "attestation claim missing 'platform_handle' field".to_owned(),
                    },
                },
                None,
            );
        }
    }

    // 7. All verifications passed. Retire the shadow by transitioning its
    //    provenance status to Claimed. This is irreversible.
    shadow.provenance_status = ShadowProvenanceStatus::Claimed;

    // 8. Produce a ShadowClaimEvent for the Merkle log.
    let event = ShadowClaimEvent {
        shadow_id: request.shadow_id.clone(),
        claimant_did: request.claimant_did.clone(),
        platform_handle: request.platform_handle.clone(),
        attestation_id: request.identity_attestation.id.clone(),
        context_id: registry.context_id().to_owned(),
        timestamp: request.timestamp,
    };

    (
        ClaimResult::Success {
            shadow_id: request.shadow_id.clone(),
            claimant_did: request.claimant_did.clone(),
        },
        Some(event),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::single_char_pattern
)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::bridge::shadow::{create_shadow, ShadowRegistry};
    use crate::bridge::{BridgeMode, ShadowProvenanceStatus};
    use crate::trust::attestation::AttestationEvidence;

    // -------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------

    const CTX: &str = "ctx-claim-test";
    const BRIDGE_ID: &str = "bridge-claim-001";
    const SHADOW_ID: &str = "shadow-claim-001";
    const HANDLE: &str = "@alice#1234";
    const CLAIMANT_DID: &str = "did:dht:z6MkAliceClaim";
    const ATTESTATION_ID: &str = "attest-claim-001";

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    fn make_registry() -> ShadowRegistry {
        ShadowRegistry::new(CTX.to_owned())
    }

    fn create_test_shadow(registry: &mut ShadowRegistry) {
        create_shadow(
            registry,
            SHADOW_ID,
            BRIDGE_ID,
            BridgeMode::Relay,
            HANDLE,
            &[],
            1_700_000_100,
        )
        .unwrap();
    }

    fn make_identity_attestation(
        subject: &str,
        platform_handle: &str,
    ) -> Attestation {
        Attestation {
            id: ATTESTATION_ID.to_owned(),
            attestation_type: AttestationType::IdentityLink,
            issuer: subject.into(),
            subject: subject.into(),
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
            renewal_interval: Some(Duration::from_secs(86_400)),
            revocation_status: RevocationStatus::Active,
            signature: vec![0u8; 64],
        }
    }

    fn make_claim_request(
        shadow_id: &str,
        claimant_did: &str,
        platform_handle: &str,
        attestation: Attestation,
    ) -> ClaimRequest {
        ClaimRequest {
            shadow_id: shadow_id.to_owned(),
            claimant_did: claimant_did.into(),
            platform_handle: platform_handle.to_owned(),
            identity_attestation: attestation,
            timestamp: 1_700_000_300,
            signature: vec![0u8; 64],
        }
    }

    fn make_default_claim_request() -> ClaimRequest {
        let attestation = make_identity_attestation(CLAIMANT_DID, HANDLE);
        make_claim_request(SHADOW_ID, CLAIMANT_DID, HANDLE, attestation)
    }

    // -------------------------------------------------------------------
    // Successful claiming
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_succeeds_with_valid_attestation() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let request = make_default_claim_request();
        let (result, event) = claim_shadow(&mut registry, &request);

        assert!(matches!(result, ClaimResult::Success { .. }));
        assert!(event.is_some());
    }

    #[test]
    fn claim_shadow_success_returns_correct_ids() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let request = make_default_claim_request();
        let (result, _event) = claim_shadow(&mut registry, &request);

        match result {
            ClaimResult::Success {
                shadow_id,
                claimant_did,
            } => {
                assert_eq!(shadow_id, SHADOW_ID);
                assert_eq!(claimant_did, CLAIMANT_DID);
            }
            ClaimResult::Failed { reason } => panic!("expected success, got: {reason}"),
        }
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
        let (result, _) = claim_shadow(&mut registry, &request);
        assert!(matches!(result, ClaimResult::Success { .. }));

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

        let request = make_default_claim_request();
        let (_result, event) = claim_shadow(&mut registry, &request);

        let event = event.expect("expected ShadowClaimEvent");
        assert_eq!(event.shadow_id, SHADOW_ID);
        assert_eq!(event.claimant_did, CLAIMANT_DID);
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
        let (result, event) = claim_shadow(&mut registry, &request);

        assert!(event.is_none());
        match result {
            ClaimResult::Failed { reason } => {
                assert!(matches!(reason, ClaimError::ShadowNotFound { .. }));
            }
            ClaimResult::Success { .. } => panic!("expected failure"),
        }
    }

    #[test]
    fn claim_shadow_fails_for_wrong_shadow_id() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let attestation = make_identity_attestation(CLAIMANT_DID, HANDLE);
        let request = make_claim_request("nonexistent-shadow", CLAIMANT_DID, HANDLE, attestation);
        let (result, event) = claim_shadow(&mut registry, &request);

        assert!(event.is_none());
        assert!(matches!(
            result,
            ClaimResult::Failed {
                reason: ClaimError::ShadowNotFound { .. }
            }
        ));
    }

    // -------------------------------------------------------------------
    // AlreadyClaimed (one-way, irreversible)
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_fails_when_already_claimed() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        // First claim succeeds.
        let request = make_default_claim_request();
        let (result, _) = claim_shadow(&mut registry, &request);
        assert!(matches!(result, ClaimResult::Success { .. }));

        // Second claim fails with AlreadyClaimed.
        let request2 = make_default_claim_request();
        let (result2, event2) = claim_shadow(&mut registry, &request2);
        assert!(event2.is_none());
        match result2 {
            ClaimResult::Failed { reason } => {
                assert!(matches!(reason, ClaimError::AlreadyClaimed { .. }));
            }
            ClaimResult::Success { .. } => panic!("expected AlreadyClaimed"),
        }
    }

    #[test]
    fn claimed_shadow_cannot_be_reassigned_to_different_did() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        // First claim by Alice.
        let request = make_default_claim_request();
        let (result, _) = claim_shadow(&mut registry, &request);
        assert!(matches!(result, ClaimResult::Success { .. }));

        // Attempt to re-claim by Bob.
        let bob_did = "did:dht:z6MkBobClaim";
        let attestation = make_identity_attestation(bob_did, HANDLE);
        let bob_request = make_claim_request(SHADOW_ID, bob_did, HANDLE, attestation);
        let (result2, event2) = claim_shadow(&mut registry, &bob_request);
        assert!(event2.is_none());
        assert!(matches!(
            result2,
            ClaimResult::Failed {
                reason: ClaimError::AlreadyClaimed { .. }
            }
        ));
    }

    // -------------------------------------------------------------------
    // HandleMismatch
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_fails_on_handle_mismatch() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        // Attestation has a different handle than the shadow.
        let attestation = make_identity_attestation(CLAIMANT_DID, "@wrong_handle");
        let request = make_claim_request(SHADOW_ID, CLAIMANT_DID, "@wrong_handle", attestation);
        let (result, event) = claim_shadow(&mut registry, &request);

        assert!(event.is_none());
        assert!(matches!(
            result,
            ClaimResult::Failed {
                reason: ClaimError::HandleMismatch
            }
        ));
    }

    // -------------------------------------------------------------------
    // AttestationInvalid -- wrong type
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_fails_for_non_identity_link_attestation() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let mut attestation = make_identity_attestation(CLAIMANT_DID, HANDLE);
        attestation.attestation_type = AttestationType::Endorsement;

        let request = make_claim_request(SHADOW_ID, CLAIMANT_DID, HANDLE, attestation);
        let (result, event) = claim_shadow(&mut registry, &request);

        assert!(event.is_none());
        match result {
            ClaimResult::Failed { reason } => {
                assert!(matches!(reason, ClaimError::AttestationInvalid { .. }));
            }
            ClaimResult::Success { .. } => panic!("expected AttestationInvalid"),
        }
    }

    #[test]
    fn claim_shadow_fails_for_capability_delegation_attestation() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let mut attestation = make_identity_attestation(CLAIMANT_DID, HANDLE);
        attestation.attestation_type = AttestationType::CapabilityDelegation;

        let request = make_claim_request(SHADOW_ID, CLAIMANT_DID, HANDLE, attestation);
        let (result, event) = claim_shadow(&mut registry, &request);

        assert!(event.is_none());
        assert!(matches!(
            result,
            ClaimResult::Failed {
                reason: ClaimError::AttestationInvalid { .. }
            }
        ));
    }

    // -------------------------------------------------------------------
    // AttestationInvalid -- subject mismatch
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_fails_when_attestation_subject_does_not_match_claimant() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        // Attestation subject is for a different DID.
        let attestation = make_identity_attestation("did:dht:z6MkOtherPerson", HANDLE);
        let request = make_claim_request(SHADOW_ID, CLAIMANT_DID, HANDLE, attestation);
        let (result, event) = claim_shadow(&mut registry, &request);

        assert!(event.is_none());
        match result {
            ClaimResult::Failed { reason } => {
                assert!(matches!(reason, ClaimError::AttestationInvalid { .. }));
            }
            ClaimResult::Success { .. } => panic!("expected AttestationInvalid"),
        }
    }

    // -------------------------------------------------------------------
    // AttestationInvalid -- revoked
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_fails_when_attestation_is_revoked() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let mut attestation = make_identity_attestation(CLAIMANT_DID, HANDLE);
        attestation.revocation_status = RevocationStatus::Revoked {
            revoked_at: 1_700_000_250,
            reason: Some("compromised".to_owned()),
        };

        let request = make_claim_request(SHADOW_ID, CLAIMANT_DID, HANDLE, attestation);
        let (result, event) = claim_shadow(&mut registry, &request);

        assert!(event.is_none());
        match result {
            ClaimResult::Failed { reason } => {
                assert!(matches!(reason, ClaimError::AttestationInvalid { .. }));
            }
            ClaimResult::Success { .. } => panic!("expected AttestationInvalid for revoked"),
        }
    }

    // -------------------------------------------------------------------
    // AttestationInvalid -- missing platform_handle in claim
    // -------------------------------------------------------------------

    #[test]
    fn claim_shadow_fails_when_attestation_claim_missing_platform_handle() {
        let mut registry = make_registry();
        create_test_shadow(&mut registry);

        let mut attestation = make_identity_attestation(CLAIMANT_DID, HANDLE);
        attestation.claim = serde_json::json!({"platform": "discord"});

        let request = make_claim_request(SHADOW_ID, CLAIMANT_DID, HANDLE, attestation);
        let (result, event) = claim_shadow(&mut registry, &request);

        assert!(event.is_none());
        match result {
            ClaimResult::Failed { reason } => {
                assert!(matches!(reason, ClaimError::AttestationInvalid { .. }));
            }
            ClaimResult::Success { .. } => {
                panic!("expected AttestationInvalid for missing handle")
            }
        }
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
            serde_json::from_str(json.as_ref().map(String::as_str).unwrap_or(""));
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
            claimant_did: CLAIMANT_DID.into(),
            platform_handle: HANDLE.to_owned(),
            attestation_id: ATTESTATION_ID.to_owned(),
            context_id: CTX.to_owned(),
            timestamp: 1_700_000_300,
        };

        let json = serde_json::to_string(&event);
        assert!(json.is_ok(), "serialization should succeed");

        let deserialized: Result<ShadowClaimEvent, _> =
            serde_json::from_str(json.as_ref().map(String::as_str).unwrap_or(""));
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
        create_shadow(
            &mut registry,
            "shadow-a",
            BRIDGE_ID,
            BridgeMode::Relay,
            "@alice",
            &[],
            1_700_000_100,
        )
        .unwrap();

        create_shadow(
            &mut registry,
            "shadow-b",
            BRIDGE_ID,
            BridgeMode::Relay,
            "@bob",
            &[],
            1_700_000_100,
        )
        .unwrap();

        // Claim shadow-a.
        let attestation = make_identity_attestation(CLAIMANT_DID, "@alice");
        let request = make_claim_request("shadow-a", CLAIMANT_DID, "@alice", attestation);
        let (result, _) = claim_shadow(&mut registry, &request);
        assert!(matches!(result, ClaimResult::Success { .. }));

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
        create_shadow(
            &mut registry,
            SHADOW_ID,
            BRIDGE_ID,
            BridgeMode::Puppet,
            HANDLE,
            &[],
            1_700_000_100,
        )
        .unwrap();

        let request = make_default_claim_request();
        let (_result, event) = claim_shadow(&mut registry, &request);

        let event = event.expect("expected event");
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

    // -------------------------------------------------------------------
    // ClaimResult variants
    // -------------------------------------------------------------------

    #[test]
    fn claim_result_success_variant_debug() {
        let result = ClaimResult::Success {
            shadow_id: "s-001".to_owned(),
            claimant_did: "did:test".into(),
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("Success"));
    }

    #[test]
    fn claim_result_failed_variant_debug() {
        let result = ClaimResult::Failed {
            reason: ClaimError::HandleMismatch,
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("Failed"));
    }
}
