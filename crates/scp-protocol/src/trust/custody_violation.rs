//! Custody violation detection, attestation, and enforcement for agent binding (ADR-039).
//!
//! This module provides:
//!
//! 1. **Violation types** (Layer 4 of the ADR-039 enforcement stack): permanent
//!    records for unambiguous custody violations. Only binary, cryptographically
//!    verifiable violations are recorded — behavioral anomalies are explicitly
//!    excluded (they are soft trust signals, not violations).
//!
//! 2. **Category A enforcement**: DID document modifications (add/remove keys,
//!    change services, alter relays, pre-rotation commitments, identity
//!    migration) MUST be signed by the human's Active Signing Key (`#active`).
//!    If an agent key (`#agent`) attempts a Category A action, the verification
//!    point rejects the action and emits a [`ScpCustodyViolationAttestation`]
//!    with the violating signature as evidence.
//!
//! # Types
//!
//! - [`ActionCategory`] — Classification of a protocol action (Category A or B).
//! - [`CustodyViolationType`] — Enumeration of unambiguous violation categories.
//! - [`ScpCustodyViolationAttestation`] — Permanent, append-only violation record.
//! - [`CounterAttestation`] — Counter-evidence for reputation restoration.
//! - [`CustodyViolationError`] — Validation errors for custody violation types.
//! - [`CustodyViolationResult`] — Result of a Category A enforcement check.
//! - [`ViolationStore`] — Trait for custody violation storage (append-only).
//! - [`InMemoryViolationStore`] — In-memory implementation for testing.
//!
//! # Action Classification
//!
//! Actions are classified by their UCAN capability resource type:
//!
//! - **Category A** (human-only): `did_document`, `verification_method`,
//!   `identity`, `pre_rotation`, `service`, `relay_config` — any resource
//!   that modifies the DID document itself.
//! - **Category B/C** (agent-permitted): `messages`, `outlet_call`, `member`,
//!   `role`, `context`, `spending`, and all other operational resources.
//!
//! The classifier is deliberately conservative: unknown resource types default
//! to Category B (agent-permitted) because Category A is a closed set defined
//! by the DID document's own structure.
//!
//! See ADR-039 in `.docs/adrs/phase-6.md` and spec section §3.6.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use scp_did::{DID, SigningKeyId};

// ---------------------------------------------------------------------------
// Action categories (AB-020)
// ---------------------------------------------------------------------------

/// Classification of a protocol action for custody enforcement.
///
/// Category A actions modify the DID document and MUST be signed by the
/// human's Active Signing Key (`#active`). Category B actions are operational
/// and may be signed by either key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionCategory {
    /// DID document modifications — human-only (`#active` key required).
    ///
    /// Includes: add/remove verification methods, change services, alter
    /// relay configuration, pre-rotation commitments, identity migration.
    CategoryA,

    /// Operational actions — agent key (`#agent`) permitted.
    ///
    /// Includes: messaging, outlet invocation, member management, role
    /// assignment, context operations, spending, and all other non-DID-
    /// document actions.
    CategoryB,
}

/// Category A resource types — the closed set of UCAN capability resource
/// types that modify the DID document.
///
/// This is a protocol constant: any resource type not in this list is
/// Category B by definition, because Category A is bounded by the DID
/// document's own structure.
const CATEGORY_A_RESOURCES: &[&str] = &[
    "did_document",
    "verification_method",
    "identity",
    "pre_rotation",
    "service",
    "relay_config",
    "did_migration",
    "key_management",
];

/// Returns the closed set of Category A resource types.
///
/// These are the UCAN capability resource types that modify the DID document
/// and therefore require human (`#active`) signing. Exposed for conformance
/// testing against mirror implementations.
///
/// # Examples
///
/// ```
/// use scp_protocol::trust::custody_violation::category_a_resources;
///
/// let resources = category_a_resources();
/// assert!(resources.contains(&"did_document"));
/// assert!(!resources.contains(&"messages"));
/// ```
#[must_use]
pub const fn category_a_resources() -> &'static [&'static str] {
    CATEGORY_A_RESOURCES
}

/// Classifies an action by its UCAN capability resource type.
///
/// Returns [`ActionCategory::CategoryA`] if the resource type modifies the
/// DID document, [`ActionCategory::CategoryB`] otherwise.
///
/// The resource type corresponds to the `{resource}` component of an SCP
/// capability URI: `scp:ctx:{context_id}/{resource}:{action}`.
///
/// # Examples
///
/// ```
/// use scp_protocol::trust::custody_violation::{classify_action, ActionCategory};
///
/// assert_eq!(classify_action("did_document"), ActionCategory::CategoryA);
/// assert_eq!(classify_action("verification_method"), ActionCategory::CategoryA);
/// assert_eq!(classify_action("messages"), ActionCategory::CategoryB);
/// assert_eq!(classify_action("outlet_call"), ActionCategory::CategoryB);
/// ```
#[must_use]
pub fn classify_action(resource: &str) -> ActionCategory {
    if CATEGORY_A_RESOURCES.contains(&resource) {
        ActionCategory::CategoryA
    } else {
        ActionCategory::CategoryB
    }
}

// ---------------------------------------------------------------------------
// CustodyViolationType (AB-019)
// ---------------------------------------------------------------------------

/// Types of unambiguous custody violations.
///
/// Only binary, cryptographically verifiable violations — no behavioral
/// signals. Each variant is either provably true or provably false based on
/// the cryptographic evidence alone.
///
/// See ADR-039 enforcement stack, Layer 4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum CustodyViolationType {
    /// Category A action (DID document modification) signed by `#agent` key.
    ///
    /// Binary — the signature either came from `#agent` or it didn't.
    /// Category A actions are protocol-immutable: only `#0` or `#active` may
    /// sign them. An `#agent` signature on a Category A action is an
    /// unambiguous custody boundary crossing.
    CategoryAViolation {
        /// The action that was attempted (e.g., `"did_document_update"`,
        /// `"pre_rotation_commitment"`, `"identity_migration"`,
        /// `"root_ucan_issuance"`).
        action: String,
        /// The signing key ID that was used (`#agent`). Stored explicitly
        /// rather than assumed, so the evidence record is self-contained.
        signer_key_id: SigningKeyId,
        /// The raw signature bytes as cryptographic evidence. Verifiers can
        /// independently confirm this signature was produced by the `#agent`
        /// key in the subject's DID document.
        signature_evidence: Vec<u8>,
    },

    /// Platform attestation contradicts observed behavior.
    ///
    /// Only when hardware proof is cryptographically verifiable — e.g., an
    /// Apple App Attest or Android Key Attestation claims `#active` is
    /// hardware-backed, but operations are observed that would require
    /// software access to that key material.
    AttestationMismatch {
        /// What the attestation claimed (e.g., `"hardware-biometric"` custody
        /// model for `#active` key).
        claimed_custody: String,
        /// What was actually observed that contradicts the claim (e.g.,
        /// `"#active key used without biometric unlock within 50ms of
        /// #agent action"`).
        observed_behavior: String,
        /// The attestation proof bytes that make the contradiction
        /// cryptographically verifiable. Without hardware proof, the
        /// mismatch is a behavioral signal (Layer 5), not a violation.
        attestation_evidence: Vec<u8>,
    },
}

// ---------------------------------------------------------------------------
// ScpCustodyViolationAttestation (AB-019)
// ---------------------------------------------------------------------------

/// Permanent record of an unambiguous custody violation.
///
/// Append-only — never deleted, never modified. These records form a
/// permanent, verifiable audit trail of custody boundary violations.
/// DID owners can publish [`CounterAttestation`] records alongside
/// violations for reputation restoration, but the violation record itself
/// is immutable.
///
/// See ADR-039 acceptance criterion 17.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScpCustodyViolationAttestation {
    /// DID of the identity whose custody boundary was violated.
    pub subject_did: DID,
    /// Unix timestamp (seconds) when the violation was detected.
    pub timestamp: u64,
    /// The violation details with cryptographic evidence.
    pub violation: CustodyViolationType,
    /// Ed25519 signature over the canonical violation record by the
    /// detecting verifier. Enables independent verification that the
    /// violation was logged by the claimed verifier.
    pub verifier_signature: Vec<u8>,
    /// DID of the verifier who detected and logged this violation.
    pub verifier_did: DID,
}

/// Validation error for custody violation types.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CustodyViolationError {
    /// Evidence bytes are empty — a violation record without cryptographic
    /// evidence is meaningless.
    #[error("evidence must not be empty: {field}")]
    EmptyEvidence {
        /// Which evidence field is empty.
        field: &'static str,
    },

    /// The verifier signature is empty.
    #[error("verifier signature must not be empty")]
    EmptyVerifierSignature,

    /// A required string field is empty.
    #[error("{field} must not be empty")]
    EmptyField {
        /// Which field is empty.
        field: &'static str,
    },

    /// Category A violation was not signed by the agent key.
    #[error("Category A violation signer_key_id must be Agent, got {0}")]
    InvalidCategoryASigner(SigningKeyId),
}

impl CustodyViolationType {
    /// Validates that the violation evidence is well-formed.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyViolationError`] if evidence bytes are empty or
    /// required string fields are blank.
    pub fn validate(&self) -> Result<(), CustodyViolationError> {
        match self {
            Self::CategoryAViolation {
                action,
                signer_key_id,
                signature_evidence,
            } => {
                if action.is_empty() {
                    return Err(CustodyViolationError::EmptyField { field: "action" });
                }
                if *signer_key_id != SigningKeyId::Agent {
                    return Err(CustodyViolationError::InvalidCategoryASigner(
                        *signer_key_id,
                    ));
                }
                if signature_evidence.is_empty() {
                    return Err(CustodyViolationError::EmptyEvidence {
                        field: "signature_evidence",
                    });
                }
                Ok(())
            }
            Self::AttestationMismatch {
                claimed_custody,
                observed_behavior,
                attestation_evidence,
            } => {
                if claimed_custody.is_empty() {
                    return Err(CustodyViolationError::EmptyField {
                        field: "claimed_custody",
                    });
                }
                if observed_behavior.is_empty() {
                    return Err(CustodyViolationError::EmptyField {
                        field: "observed_behavior",
                    });
                }
                if attestation_evidence.is_empty() {
                    return Err(CustodyViolationError::EmptyEvidence {
                        field: "attestation_evidence",
                    });
                }
                Ok(())
            }
        }
    }
}

impl ScpCustodyViolationAttestation {
    /// Validates that all fields are well-formed.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyViolationError`] if the violation evidence is invalid
    /// or the verifier signature is empty.
    pub fn validate(&self) -> Result<(), CustodyViolationError> {
        self.violation.validate()?;
        if self.verifier_signature.is_empty() {
            return Err(CustodyViolationError::EmptyVerifierSignature);
        }
        Ok(())
    }

    /// Creates a new custody violation attestation, validating all fields.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyViolationError`] if:
    /// - The violation evidence is empty or malformed
    /// - The verifier signature is empty
    pub fn new(
        subject_did: DID,
        timestamp: u64,
        violation: CustodyViolationType,
        verifier_signature: Vec<u8>,
        verifier_did: DID,
    ) -> Result<Self, CustodyViolationError> {
        violation.validate()?;
        if verifier_signature.is_empty() {
            return Err(CustodyViolationError::EmptyVerifierSignature);
        }
        Ok(Self {
            subject_did,
            timestamp,
            violation,
            verifier_signature,
            verifier_did,
        })
    }

    /// Returns the violation type variant without the evidence payload.
    #[must_use]
    pub const fn violation_kind(&self) -> &'static str {
        match &self.violation {
            CustodyViolationType::CategoryAViolation { .. } => "CategoryAViolation",
            CustodyViolationType::AttestationMismatch { .. } => "AttestationMismatch",
        }
    }
}

// ---------------------------------------------------------------------------
// CounterAttestation (AB-019)
// ---------------------------------------------------------------------------

/// Counter-attestation for reputation restoration.
///
/// Published by the DID owner alongside violation records. Append-only —
/// does not erase violations, only adds context. The human signs this with
/// `#active` (not `#agent`) to demonstrate human involvement in the
/// counter-claim.
///
/// See ADR-039 acceptance criterion 18.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CounterAttestation {
    /// DID of the identity providing counter-evidence.
    pub subject_did: DID,
    /// Reference to the specific violation being contested. This should be
    /// a content-addressable identifier (e.g., hash of the violation record)
    /// that uniquely identifies the violation.
    pub violation_reference: String,
    /// Human-readable explanation of the counter-claim.
    pub explanation: String,
    /// Unix timestamp (seconds) when the counter-attestation was published.
    pub timestamp: u64,
    /// Ed25519 signature by the subject's `#active` key (human, not agent).
    /// Using the human key proves the counter-claim has human authorization.
    pub signature: Vec<u8>,
}

impl CounterAttestation {
    /// Validates that all fields are well-formed.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyViolationError`] if any required field is empty.
    pub const fn validate(&self) -> Result<(), CustodyViolationError> {
        if self.violation_reference.is_empty() {
            return Err(CustodyViolationError::EmptyField {
                field: "violation_reference",
            });
        }
        if self.explanation.is_empty() {
            return Err(CustodyViolationError::EmptyField {
                field: "explanation",
            });
        }
        if self.signature.is_empty() {
            return Err(CustodyViolationError::EmptyField { field: "signature" });
        }
        Ok(())
    }

    /// Creates a new counter-attestation, validating all fields.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyViolationError`] if:
    /// - The violation reference is empty
    /// - The explanation is empty
    /// - The signature is empty
    pub fn new(
        subject_did: DID,
        violation_reference: String,
        explanation: String,
        timestamp: u64,
        signature: Vec<u8>,
    ) -> Result<Self, CustodyViolationError> {
        if violation_reference.is_empty() {
            return Err(CustodyViolationError::EmptyField {
                field: "violation_reference",
            });
        }
        if explanation.is_empty() {
            return Err(CustodyViolationError::EmptyField {
                field: "explanation",
            });
        }
        if signature.is_empty() {
            return Err(CustodyViolationError::EmptyField { field: "signature" });
        }
        Ok(Self {
            subject_did,
            violation_reference,
            explanation,
            timestamp,
            signature,
        })
    }
}

// ---------------------------------------------------------------------------
// Custom Deserialize implementations — validate invariants on deserialization
// ---------------------------------------------------------------------------

impl<'de> Deserialize<'de> for CustodyViolationType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        enum Helper {
            CategoryAViolation {
                action: String,
                signer_key_id: SigningKeyId,
                signature_evidence: Vec<u8>,
            },
            AttestationMismatch {
                claimed_custody: String,
                observed_behavior: String,
                attestation_evidence: Vec<u8>,
            },
        }

        let helper = Helper::deserialize(deserializer)?;
        let value = match helper {
            Helper::CategoryAViolation {
                action,
                signer_key_id,
                signature_evidence,
            } => Self::CategoryAViolation {
                action,
                signer_key_id,
                signature_evidence,
            },
            Helper::AttestationMismatch {
                claimed_custody,
                observed_behavior,
                attestation_evidence,
            } => Self::AttestationMismatch {
                claimed_custody,
                observed_behavior,
                attestation_evidence,
            },
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl<'de> Deserialize<'de> for ScpCustodyViolationAttestation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            subject_did: DID,
            timestamp: u64,
            violation: CustodyViolationType,
            verifier_signature: Vec<u8>,
            verifier_did: DID,
        }

        let helper = Helper::deserialize(deserializer)?;
        let value = Self {
            subject_did: helper.subject_did,
            timestamp: helper.timestamp,
            violation: helper.violation,
            verifier_signature: helper.verifier_signature,
            verifier_did: helper.verifier_did,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl<'de> Deserialize<'de> for CounterAttestation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            subject_did: DID,
            violation_reference: String,
            explanation: String,
            timestamp: u64,
            signature: Vec<u8>,
        }

        let helper = Helper::deserialize(deserializer)?;
        let value = Self {
            subject_did: helper.subject_did,
            violation_reference: helper.violation_reference,
            explanation: helper.explanation,
            timestamp: helper.timestamp,
            signature: helper.signature,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

// ---------------------------------------------------------------------------
// Enforcement result (AB-020)
// ---------------------------------------------------------------------------

/// Result of a Category A enforcement check.
///
/// When enforcement detects a violation, it returns both the error message
/// and a summary. The caller decides how to handle the violation
/// (persist, broadcast, both, or neither).
#[derive(Debug, Clone)]
pub struct CustodyViolationResult {
    /// Human-readable error message describing the violation.
    pub error_message: String,

    /// The DID of the entity whose agent key committed the violation.
    pub violator_did: String,

    /// The signing key identifier that was used.
    pub signing_key_id: SigningKeyId,

    /// Human-readable description of the attempted action.
    pub attempted_action: String,
}

/// Checks whether a signing key is permitted to perform an action of the
/// given category.
///
/// Returns `Ok(())` if the action is permitted, or
/// `Err(CustodyViolationResult)` if an agent key attempted a Category A
/// action.
///
/// This is the core enforcement primitive used by all verification points
/// (inner envelope, UCAN validation, sender key protocol).
///
/// # Arguments
///
/// * `signing_key_id` — Which key signed the action.
/// * `category` — The action category (A or B).
/// * `violator_did` — The DID of the entity performing the action.
/// * `action_description` — Human-readable description for the attestation.
/// * `evidence_signature` — The actual signature bytes for evidence.
///
/// # Errors
///
/// Returns [`CustodyViolationResult`] if `signing_key_id` is
/// [`SigningKeyId::Agent`] and `category` is [`ActionCategory::CategoryA`].
pub fn enforce_category_a(
    signing_key_id: SigningKeyId,
    category: ActionCategory,
    violator_did: &str,
    action_description: &str,
    _evidence_signature: &[u8],
) -> Result<(), CustodyViolationResult> {
    // Only Category A actions signed by agent keys are violations.
    if category == ActionCategory::CategoryA && signing_key_id == SigningKeyId::Agent {
        return Err(CustodyViolationResult {
            error_message: format!(
                "Category A action rejected: agent key ({signing_key_id}) \
                 cannot perform DID document modification ({action_description})"
            ),
            violator_did: violator_did.to_owned(),
            signing_key_id,
            attempted_action: action_description.to_owned(),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// ViolationStore trait (AB-019)
// ---------------------------------------------------------------------------

/// Trait for custody violation storage.
///
/// Implementations must enforce append-only semantics: once a violation is
/// logged, it cannot be deleted or modified. Counter-attestations augment
/// but never remove violations.
///
/// See ADR-039 acceptance criteria 17-18.
pub trait ViolationStore {
    /// Log a custody violation attestation.
    ///
    /// Validates the attestation before storing.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyViolationError`] if the attestation fails structural
    /// validation.
    fn log_violation(
        &mut self,
        attestation: ScpCustodyViolationAttestation,
    ) -> Result<(), CustodyViolationError>;

    /// Log a counter-attestation against a previously recorded violation.
    ///
    /// Validates the counter-attestation before storing.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyViolationError`] if the counter-attestation fails
    /// structural validation.
    fn log_counter_attestation(
        &mut self,
        counter: CounterAttestation,
    ) -> Result<(), CustodyViolationError>;

    /// Retrieve all violation attestations for a DID.
    ///
    /// Returns an empty vec if no violations have been recorded for the DID.
    fn get_violations_for_did(&self, did: &DID) -> Vec<&ScpCustodyViolationAttestation>;

    /// Retrieve all counter-attestations for a DID.
    ///
    /// Returns counter-attestations where `subject_did` matches the given DID.
    fn get_counter_attestations_for_did(&self, did: &DID) -> Vec<&CounterAttestation>;
}

// ---------------------------------------------------------------------------
// InMemoryViolationStore
// ---------------------------------------------------------------------------

/// In-memory implementation of [`ViolationStore`].
///
/// Suitable for testing and short-lived processes. Production deployments
/// should use a persistent store via the `Storage` trait.
#[derive(Debug, Default)]
pub struct InMemoryViolationStore {
    /// Violations keyed by subject DID.
    violations: HashMap<DID, Vec<ScpCustodyViolationAttestation>>,

    /// Counter-attestations keyed by subject DID.
    counter_attestations: HashMap<DID, Vec<CounterAttestation>>,
}

impl InMemoryViolationStore {
    /// Create a new empty in-memory violation store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ViolationStore for InMemoryViolationStore {
    fn log_violation(
        &mut self,
        attestation: ScpCustodyViolationAttestation,
    ) -> Result<(), CustodyViolationError> {
        attestation.validate()?;
        let did = attestation.subject_did.clone();
        self.violations.entry(did).or_default().push(attestation);
        Ok(())
    }

    fn log_counter_attestation(
        &mut self,
        counter: CounterAttestation,
    ) -> Result<(), CustodyViolationError> {
        counter.validate()?;
        let did = counter.subject_did.clone();
        self.counter_attestations
            .entry(did)
            .or_default()
            .push(counter);
        Ok(())
    }

    fn get_violations_for_did(&self, did: &DID) -> Vec<&ScpCustodyViolationAttestation> {
        self.violations
            .get(did)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    fn get_counter_attestations_for_did(&self, did: &DID) -> Vec<&CounterAttestation> {
        self.counter_attestations
            .get(did)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn test_did(name: &str) -> DID {
        DID(format!("did:dht:{name}"))
    }

    // -------------------------------------------------------------------
    // classify_action tests (AB-020)
    // -------------------------------------------------------------------

    #[test]
    fn classify_did_document_as_category_a() {
        assert_eq!(classify_action("did_document"), ActionCategory::CategoryA);
    }

    #[test]
    fn classify_verification_method_as_category_a() {
        assert_eq!(
            classify_action("verification_method"),
            ActionCategory::CategoryA
        );
    }

    #[test]
    fn classify_identity_as_category_a() {
        assert_eq!(classify_action("identity"), ActionCategory::CategoryA);
    }

    #[test]
    fn classify_pre_rotation_as_category_a() {
        assert_eq!(classify_action("pre_rotation"), ActionCategory::CategoryA);
    }

    #[test]
    fn classify_service_as_category_a() {
        assert_eq!(classify_action("service"), ActionCategory::CategoryA);
    }

    #[test]
    fn classify_relay_config_as_category_a() {
        assert_eq!(classify_action("relay_config"), ActionCategory::CategoryA);
    }

    #[test]
    fn classify_did_migration_as_category_a() {
        assert_eq!(classify_action("did_migration"), ActionCategory::CategoryA);
    }

    #[test]
    fn classify_key_management_as_category_a() {
        assert_eq!(classify_action("key_management"), ActionCategory::CategoryA);
    }

    #[test]
    fn classify_messages_as_category_b() {
        assert_eq!(classify_action("messages"), ActionCategory::CategoryB);
    }

    #[test]
    fn classify_outlet_call_as_category_b() {
        assert_eq!(classify_action("outlet_call"), ActionCategory::CategoryB);
    }

    #[test]
    fn classify_member_as_category_b() {
        assert_eq!(classify_action("member"), ActionCategory::CategoryB);
    }

    #[test]
    fn classify_role_as_category_b() {
        assert_eq!(classify_action("role"), ActionCategory::CategoryB);
    }

    #[test]
    fn classify_context_as_category_b() {
        assert_eq!(classify_action("context"), ActionCategory::CategoryB);
    }

    #[test]
    fn classify_spending_as_category_b() {
        assert_eq!(classify_action("spending"), ActionCategory::CategoryB);
    }

    #[test]
    fn classify_unknown_resource_as_category_b() {
        assert_eq!(
            classify_action("unknown_resource"),
            ActionCategory::CategoryB
        );
    }

    #[test]
    fn classify_empty_string_as_category_b() {
        assert_eq!(classify_action(""), ActionCategory::CategoryB);
    }

    // -------------------------------------------------------------------
    // enforce_category_a tests (AB-020)
    // -------------------------------------------------------------------

    #[test]
    fn agent_key_category_a_rejected() {
        let result = enforce_category_a(
            SigningKeyId::Agent,
            ActionCategory::CategoryA,
            "did:dht:alice",
            "add verification method",
            &[0xAB; 64],
        );
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(violation.violator_did, "did:dht:alice");
        assert_eq!(violation.signing_key_id, SigningKeyId::Agent);
        assert_eq!(violation.attempted_action, "add verification method");
        assert!(
            violation
                .error_message
                .contains("Category A action rejected")
        );
    }

    #[test]
    fn agent_key_category_b_accepted() {
        let result = enforce_category_a(
            SigningKeyId::Agent,
            ActionCategory::CategoryB,
            "did:dht:alice",
            "send message",
            &[0xAB; 64],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn active_key_category_a_accepted() {
        let result = enforce_category_a(
            SigningKeyId::Active,
            ActionCategory::CategoryA,
            "did:dht:alice",
            "add verification method",
            &[0xAB; 64],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn active_key_category_b_accepted() {
        let result = enforce_category_a(
            SigningKeyId::Active,
            ActionCategory::CategoryB,
            "did:dht:alice",
            "send message",
            &[0xAB; 64],
        );
        assert!(result.is_ok());
    }

    // -------------------------------------------------------------------
    // SigningKeyId tests (AB-019)
    // -------------------------------------------------------------------

    #[test]
    fn signing_key_id_serializes_to_fragment() {
        let active_json = serde_json::to_string(&SigningKeyId::Active).unwrap();
        assert_eq!(active_json, "\"#active\"");

        let agent_json = serde_json::to_string(&SigningKeyId::Agent).unwrap();
        assert_eq!(agent_json, "\"#agent\"");
    }

    #[test]
    fn signing_key_id_deserializes_from_fragment() {
        let active: SigningKeyId = serde_json::from_str("\"#active\"").unwrap();
        assert_eq!(active, SigningKeyId::Active);

        let agent: SigningKeyId = serde_json::from_str("\"#agent\"").unwrap();
        assert_eq!(agent, SigningKeyId::Agent);
    }

    #[test]
    fn signing_key_id_rejects_unknown_fragment() {
        let result = serde_json::from_str::<SigningKeyId>("\"#unknown\"");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unknown SigningKeyId"), "error was: {err}");
    }

    #[test]
    fn signing_key_id_roundtrip() {
        for key_id in [SigningKeyId::Active, SigningKeyId::Agent] {
            let json = serde_json::to_string(&key_id).unwrap();
            let back: SigningKeyId = serde_json::from_str(&json).unwrap();
            assert_eq!(key_id, back);
        }
    }

    #[test]
    fn signing_key_id_display() {
        assert_eq!(SigningKeyId::Active.to_string(), "#active");
        assert_eq!(SigningKeyId::Agent.to_string(), "#agent");
    }

    #[test]
    fn signing_key_id_as_fragment() {
        assert_eq!(SigningKeyId::Active.as_fragment(), "#active");
        assert_eq!(SigningKeyId::Agent.as_fragment(), "#agent");
    }

    // -------------------------------------------------------------------
    // CustodyViolationType: CategoryAViolation (AB-019)
    // -------------------------------------------------------------------

    #[test]
    fn category_a_violation_valid() {
        let violation = CustodyViolationType::CategoryAViolation {
            action: "did_document_update".to_string(),
            signer_key_id: SigningKeyId::Agent,
            signature_evidence: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        assert!(violation.validate().is_ok());
    }

    #[test]
    fn category_a_violation_rejects_empty_action() {
        let violation = CustodyViolationType::CategoryAViolation {
            action: String::new(),
            signer_key_id: SigningKeyId::Agent,
            signature_evidence: vec![0x01],
        };
        let err = violation.validate().unwrap_err();
        assert!(matches!(
            err,
            CustodyViolationError::EmptyField { field: "action" }
        ));
    }

    #[test]
    fn category_a_violation_rejects_active_signer() {
        let violation = CustodyViolationType::CategoryAViolation {
            action: "did_document_update".to_string(),
            signer_key_id: SigningKeyId::Active,
            signature_evidence: vec![0x01],
        };
        let err = violation.validate().unwrap_err();
        assert!(matches!(
            err,
            CustodyViolationError::InvalidCategoryASigner(SigningKeyId::Active)
        ));
    }

    #[test]
    fn category_a_violation_rejects_empty_evidence() {
        let violation = CustodyViolationType::CategoryAViolation {
            action: "did_document_update".to_string(),
            signer_key_id: SigningKeyId::Agent,
            signature_evidence: vec![],
        };
        let err = violation.validate().unwrap_err();
        assert!(matches!(
            err,
            CustodyViolationError::EmptyEvidence {
                field: "signature_evidence"
            }
        ));
    }

    // -------------------------------------------------------------------
    // CustodyViolationType: AttestationMismatch (AB-019)
    // -------------------------------------------------------------------

    #[test]
    fn attestation_mismatch_valid() {
        let violation = CustodyViolationType::AttestationMismatch {
            claimed_custody: "hardware-biometric".to_string(),
            observed_behavior: "#active key used without biometric unlock".to_string(),
            attestation_evidence: vec![0xCA, 0xFE],
        };
        assert!(violation.validate().is_ok());
    }

    #[test]
    fn attestation_mismatch_rejects_empty_claimed() {
        let violation = CustodyViolationType::AttestationMismatch {
            claimed_custody: String::new(),
            observed_behavior: "something".to_string(),
            attestation_evidence: vec![0x01],
        };
        let err = violation.validate().unwrap_err();
        assert!(matches!(
            err,
            CustodyViolationError::EmptyField {
                field: "claimed_custody"
            }
        ));
    }

    #[test]
    fn attestation_mismatch_rejects_empty_observed() {
        let violation = CustodyViolationType::AttestationMismatch {
            claimed_custody: "hardware-biometric".to_string(),
            observed_behavior: String::new(),
            attestation_evidence: vec![0x01],
        };
        let err = violation.validate().unwrap_err();
        assert!(matches!(
            err,
            CustodyViolationError::EmptyField {
                field: "observed_behavior"
            }
        ));
    }

    #[test]
    fn attestation_mismatch_rejects_empty_evidence() {
        let violation = CustodyViolationType::AttestationMismatch {
            claimed_custody: "hardware-biometric".to_string(),
            observed_behavior: "something observed".to_string(),
            attestation_evidence: vec![],
        };
        let err = violation.validate().unwrap_err();
        assert!(matches!(
            err,
            CustodyViolationError::EmptyEvidence {
                field: "attestation_evidence"
            }
        ));
    }

    // -------------------------------------------------------------------
    // ScpCustodyViolationAttestation (AB-019)
    // -------------------------------------------------------------------

    fn sample_category_a_violation() -> CustodyViolationType {
        CustodyViolationType::CategoryAViolation {
            action: "did_document_update".to_string(),
            signer_key_id: SigningKeyId::Agent,
            signature_evidence: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }
    }

    fn sample_attestation_mismatch() -> CustodyViolationType {
        CustodyViolationType::AttestationMismatch {
            claimed_custody: "hardware-biometric".to_string(),
            observed_behavior: "#active key used without biometric unlock within 50ms".to_string(),
            attestation_evidence: vec![0xCA, 0xFE, 0xBA, 0xBE],
        }
    }

    #[test]
    fn violation_attestation_new_category_a() {
        let att = ScpCustodyViolationAttestation::new(
            test_did("subject"),
            1_700_000_000,
            sample_category_a_violation(),
            vec![0x01, 0x02, 0x03],
            test_did("verifier"),
        )
        .unwrap();

        assert_eq!(att.subject_did, test_did("subject"));
        assert_eq!(att.timestamp, 1_700_000_000);
        assert_eq!(att.verifier_did, test_did("verifier"));
        assert_eq!(att.violation_kind(), "CategoryAViolation");
    }

    #[test]
    fn violation_attestation_new_attestation_mismatch() {
        let att = ScpCustodyViolationAttestation::new(
            test_did("subject"),
            1_700_000_000,
            sample_attestation_mismatch(),
            vec![0x01, 0x02, 0x03],
            test_did("verifier"),
        )
        .unwrap();

        assert_eq!(att.violation_kind(), "AttestationMismatch");
    }

    #[test]
    fn violation_attestation_rejects_empty_verifier_signature() {
        let err = ScpCustodyViolationAttestation::new(
            test_did("subject"),
            1_700_000_000,
            sample_category_a_violation(),
            vec![],
            test_did("verifier"),
        )
        .unwrap_err();

        assert!(matches!(err, CustodyViolationError::EmptyVerifierSignature));
    }

    #[test]
    fn violation_attestation_propagates_violation_validation_error() {
        let bad_violation = CustodyViolationType::CategoryAViolation {
            action: String::new(),
            signer_key_id: SigningKeyId::Agent,
            signature_evidence: vec![0x01],
        };
        let err = ScpCustodyViolationAttestation::new(
            test_did("subject"),
            1_700_000_000,
            bad_violation,
            vec![0x01],
            test_did("verifier"),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            CustodyViolationError::EmptyField { field: "action" }
        ));
    }

    #[test]
    fn violation_attestation_serialize_roundtrip() {
        let att = ScpCustodyViolationAttestation::new(
            test_did("subject"),
            1_700_000_000,
            sample_category_a_violation(),
            vec![0x01, 0x02, 0x03],
            test_did("verifier"),
        )
        .unwrap();

        let json = serde_json::to_string(&att).unwrap();
        let back: ScpCustodyViolationAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(att, back);
    }

    #[test]
    fn violation_attestation_mismatch_serialize_roundtrip() {
        let att = ScpCustodyViolationAttestation::new(
            test_did("subject"),
            1_700_000_000,
            sample_attestation_mismatch(),
            vec![0x01, 0x02, 0x03],
            test_did("verifier"),
        )
        .unwrap();

        let json = serde_json::to_string(&att).unwrap();
        let back: ScpCustodyViolationAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(att, back);
    }

    // -------------------------------------------------------------------
    // CounterAttestation (AB-019)
    // -------------------------------------------------------------------

    #[test]
    fn counter_attestation_new_valid() {
        let ca = CounterAttestation::new(
            test_did("subject"),
            "sha256:abc123".to_string(),
            "Key was rotated before the violation timestamp".to_string(),
            1_700_001_000,
            vec![0xAA, 0xBB, 0xCC],
        )
        .unwrap();

        assert_eq!(ca.subject_did, test_did("subject"));
        assert_eq!(ca.violation_reference, "sha256:abc123");
        assert_eq!(ca.timestamp, 1_700_001_000);
    }

    #[test]
    fn counter_attestation_rejects_empty_violation_reference() {
        let err = CounterAttestation::new(
            test_did("subject"),
            String::new(),
            "explanation".to_string(),
            1_700_001_000,
            vec![0x01],
        )
        .unwrap_err();

        assert!(matches!(
            err,
            CustodyViolationError::EmptyField {
                field: "violation_reference"
            }
        ));
    }

    #[test]
    fn counter_attestation_rejects_empty_explanation() {
        let err = CounterAttestation::new(
            test_did("subject"),
            "sha256:abc123".to_string(),
            String::new(),
            1_700_001_000,
            vec![0x01],
        )
        .unwrap_err();

        assert!(matches!(
            err,
            CustodyViolationError::EmptyField {
                field: "explanation"
            }
        ));
    }

    #[test]
    fn counter_attestation_rejects_empty_signature() {
        let err = CounterAttestation::new(
            test_did("subject"),
            "sha256:abc123".to_string(),
            "explanation".to_string(),
            1_700_001_000,
            vec![],
        )
        .unwrap_err();

        assert!(matches!(
            err,
            CustodyViolationError::EmptyField { field: "signature" }
        ));
    }

    #[test]
    fn counter_attestation_serialize_roundtrip() {
        let ca = CounterAttestation::new(
            test_did("subject"),
            "sha256:abc123".to_string(),
            "Key was rotated before the violation timestamp".to_string(),
            1_700_001_000,
            vec![0xAA, 0xBB, 0xCC],
        )
        .unwrap();

        let json = serde_json::to_string(&ca).unwrap();
        let back: CounterAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(ca, back);
    }

    #[test]
    fn counter_attestation_references_specific_violation() {
        let violation = ScpCustodyViolationAttestation::new(
            test_did("alice"),
            1_700_000_000,
            sample_category_a_violation(),
            vec![0x01, 0x02],
            test_did("verifier"),
        )
        .unwrap();

        let reference = format!(
            "{}:{}:{}",
            violation.violation_kind(),
            violation.subject_did.0,
            violation.timestamp
        );

        let counter = CounterAttestation::new(
            test_did("alice"),
            reference.clone(),
            "Agent key was compromised; rotated immediately after detection".to_string(),
            1_700_001_000,
            vec![0xAA, 0xBB],
        )
        .unwrap();

        assert_eq!(counter.violation_reference, reference);
        assert_eq!(counter.subject_did, violation.subject_did);
        assert!(counter.timestamp > violation.timestamp);
    }

    // -------------------------------------------------------------------
    // Deserialization validation (AB-019)
    // -------------------------------------------------------------------

    #[test]
    fn deser_category_a_rejects_active_signer() {
        let json = serde_json::json!({
            "CategoryAViolation": {
                "action": "did_document_update",
                "signer_key_id": "#active",
                "signature_evidence": [0xDE, 0xAD]
            }
        });
        let result = serde_json::from_value::<CustodyViolationType>(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Category A violation signer_key_id must be Agent"),
            "error was: {err}"
        );
    }

    #[test]
    fn deser_category_a_rejects_empty_evidence() {
        let json = serde_json::json!({
            "CategoryAViolation": {
                "action": "did_document_update",
                "signer_key_id": "#agent",
                "signature_evidence": []
            }
        });
        let result = serde_json::from_value::<CustodyViolationType>(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("evidence must not be empty"),
            "error was: {err}"
        );
    }

    #[test]
    fn deser_attestation_rejects_empty_verifier_signature() {
        let json = serde_json::json!({
            "subject_did": "did:dht:subject",
            "timestamp": 1_700_000_000,
            "violation": {
                "CategoryAViolation": {
                    "action": "did_document_update",
                    "signer_key_id": "#agent",
                    "signature_evidence": [0xDE, 0xAD]
                }
            },
            "verifier_signature": [],
            "verifier_did": "did:dht:verifier"
        });
        let result = serde_json::from_value::<ScpCustodyViolationAttestation>(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("verifier signature must not be empty"),
            "error was: {err}"
        );
    }

    #[test]
    fn deser_counter_attestation_rejects_empty_explanation() {
        let json = serde_json::json!({
            "subject_did": "did:dht:subject",
            "violation_reference": "sha256:abc123",
            "explanation": "",
            "timestamp": 1_700_001_000,
            "signature": [0xAA, 0xBB]
        });
        let result = serde_json::from_value::<CounterAttestation>(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("explanation must not be empty"),
            "error was: {err}"
        );
    }

    // -------------------------------------------------------------------
    // ActionCategory serialization (AB-020)
    // -------------------------------------------------------------------

    #[test]
    fn action_category_serialization_roundtrip() {
        for cat in [ActionCategory::CategoryA, ActionCategory::CategoryB] {
            let json = serde_json::to_string(&cat).unwrap();
            let deserialized: ActionCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, deserialized);
        }
    }

    // -------------------------------------------------------------------
    // ViolationStore tests (AB-019)
    // -------------------------------------------------------------------

    fn make_test_violation(subject: &str, action: &str) -> ScpCustodyViolationAttestation {
        ScpCustodyViolationAttestation {
            subject_did: DID(subject.to_string()),
            timestamp: 1_700_000_000,
            violation: CustodyViolationType::CategoryAViolation {
                action: action.to_string(),
                signer_key_id: SigningKeyId::Agent,
                signature_evidence: vec![0xDE, 0xAD],
            },
            verifier_signature: vec![0xAA, 0xBB],
            verifier_did: DID("did:dht:verifier".to_string()),
        }
    }

    fn make_test_counter(subject: &str, violation_ref: &str) -> CounterAttestation {
        CounterAttestation {
            subject_did: DID(subject.to_string()),
            violation_reference: violation_ref.to_string(),
            explanation: "key rotated, incident resolved".to_string(),
            timestamp: 1_700_001_000,
            signature: vec![0xCC, 0xDD],
        }
    }

    #[test]
    fn violation_store_log_and_retrieve() {
        let mut store = InMemoryViolationStore::new();
        let did = DID("did:dht:alice".to_string());
        let violation = make_test_violation("did:dht:alice", "did_document_update");

        store.log_violation(violation).unwrap();

        let results = store.get_violations_for_did(&did);
        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0].violation,
            CustodyViolationType::CategoryAViolation { action, .. }
                if action == "did_document_update"
        ));
    }

    #[test]
    fn violation_store_multiple_dids() {
        let mut store = InMemoryViolationStore::new();

        store
            .log_violation(make_test_violation("did:dht:alice", "did_document_update"))
            .unwrap();
        store
            .log_violation(make_test_violation("did:dht:bob", "pre_rotation"))
            .unwrap();
        store
            .log_violation(make_test_violation("did:dht:alice", "identity_migration"))
            .unwrap();

        let alice_did = DID("did:dht:alice".to_string());
        let bob_did = DID("did:dht:bob".to_string());

        assert_eq!(store.get_violations_for_did(&alice_did).len(), 2);
        assert_eq!(store.get_violations_for_did(&bob_did).len(), 1);
    }

    #[test]
    fn violation_store_counter_attestation() {
        let mut store = InMemoryViolationStore::new();

        store
            .log_violation(make_test_violation("did:dht:alice", "did_document_update"))
            .unwrap();

        let counter = make_test_counter("did:dht:alice", "violation-hash-abc");
        store.log_counter_attestation(counter).unwrap();

        let alice_did = DID("did:dht:alice".to_string());
        let counters = store.get_counter_attestations_for_did(&alice_did);
        assert_eq!(counters.len(), 1);
        assert_eq!(counters[0].violation_reference, "violation-hash-abc");
    }

    #[test]
    fn violation_store_empty_query() {
        let store = InMemoryViolationStore::new();
        let nobody = DID("did:dht:nobody".to_string());

        assert!(store.get_violations_for_did(&nobody).is_empty());
        assert!(store.get_counter_attestations_for_did(&nobody).is_empty());
    }

    #[test]
    fn violation_store_append_only() {
        let mut store = InMemoryViolationStore::new();

        store
            .log_violation(make_test_violation("did:dht:alice", "did_document_update"))
            .unwrap();
        let alice_did = DID("did:dht:alice".to_string());
        assert_eq!(store.get_violations_for_did(&alice_did).len(), 1);

        store
            .log_violation(make_test_violation("did:dht:alice", "pre_rotation"))
            .unwrap();
        assert_eq!(store.get_violations_for_did(&alice_did).len(), 2);

        // Both violations preserved in order.
        let violations = store.get_violations_for_did(&alice_did);
        assert!(matches!(
            &violations[0].violation,
            CustodyViolationType::CategoryAViolation { action, .. }
                if action == "did_document_update"
        ));
        assert!(matches!(
            &violations[1].violation,
            CustodyViolationType::CategoryAViolation { action, .. }
                if action == "pre_rotation"
        ));
    }
}
