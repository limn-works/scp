//! Custody violation detection, attestation, and enforcement for agent binding (ADR-039).
//!
//! This module provides:
//!
//! 1. **Violation types** (Layer 4 of the ADR-039 enforcement stack): permanent
//!    records for unambiguous custody violations. Only binary, cryptographically
//!    verifiable violations are recorded — behavioral anomalies are explicitly
//!    excluded (they are soft trust signals, not violations).
//!
//! 2. **Category A enforcement**: an agent key (`#agent`) MUST NOT sign a
//!    Category A action. When one does, the verification point rejects the
//!    action and emits a [`ScpCustodyViolationAttestation`] with the violating
//!    signature as evidence. ADR-039 reserves each Category A action to a
//!    named human key: a DID-document write (add/remove keys, change services,
//!    alter relays, pre-rotation commitments, identity migration) requires the
//!    Identity Key (`#0`), and root UCAN issuance requires the Active Signing
//!    Key (`#active`). Spec §4.9.1 states the membership criterion for each
//!    reservation.
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
//! ADR-039 defines three permission categories. Category A and Category B
//! partition the protocol's actions and answer one question — who writes the
//! signing-key rule for this action, the protocol or the DID's owner. Category
//! C partitions nothing: it is a second axis on which a context restricts what
//! an agent may do inside that context. [`classify_action`] answers the first
//! question only, so a [`ActionCategory::CategoryB`] verdict says the protocol
//! leaves the rule to the DID's owner, and says nothing about whether any
//! context admits the action. Spec §4.9 states all three categories and §4.9.4
//! states what a verifier does when the two axes disagree.
//!
//! Actions are classified by their UCAN capability resource type:
//!
//! - **Category A** (agent key MUST NOT sign): every resource type that names
//!   a write to the DID document — see `CATEGORY_A_RESOURCES`, whose doc
//!   comment states both membership criteria and names the one entry that
//!   satisfies neither.
//! - **Category B** (agent key may sign what its human permits): `messages`,
//!   `outlet_call`, `member`, `role`, `context`, `spending`, and every other
//!   operational resource.
//!
//! [`classify_action`] reads a resource token, so it recognizes only the
//! Category A actions a resource token names. Root UCAN issuance is Category A
//! and no resource token names it, so no verdict from this function reports
//! it; `enforce_ucan_category_a` reads the token's `prf` for that rule instead.
//! A reader who takes a [`ActionCategory::CategoryB`] verdict as "the agent key
//! may sign this artifact" reaches the wrong answer on a root UCAN.
//!
//! The classifier is deliberately conservative: unknown resource types default
//! to Category B because Category A is a closed set defined by the DID
//! document's own structure.
//!
//! See ADR-039, the shared-DID human-agent identity model, in
//! `.docs/adrs/phase-1.md`, and spec §4.9 in `.docs/specs/04-agents.md`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use scp_did::{DID, SigningKeyId};

// ---------------------------------------------------------------------------
// Action categories (AB-020)
// ---------------------------------------------------------------------------

/// Classification of a protocol action for custody enforcement.
///
/// The protocol fixes the signing-key rule for a Category A action and leaves
/// the rule for a Category B action to the human who owns the DID. Neither
/// verdict speaks for Category C, which a context sets on its own axis
/// (§4.9.3, §4.9.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionCategory {
    /// DID document writes — the agent key (`#agent`) MUST NOT sign one, and
    /// ADR-039 reserves the write itself to the Identity Key (`#0`).
    ///
    /// Includes: add/remove verification methods, change services, alter
    /// relay configuration, pre-rotation commitments, identity migration.
    CategoryA,

    /// Operational actions — the agent key (`#agent`) signs the ones its
    /// human enumerated in `fct.scp_agent_permissions` (§4.9.2), and the
    /// context the action runs in may still forbid it (§4.9.3).
    ///
    /// Includes: messaging, outlet invocation, member management, role
    /// assignment, context operations, spending, and all other non-DID-
    /// document actions.
    CategoryB,
}

/// Category A resource types — the UCAN capability resource types that name a
/// write to the DID document.
///
/// **The criteria** (spec §4.9.1). Two criteria decide Category A membership,
/// and each names the key the action is reserved to. An action is reserved to
/// `#0` when exercising a capability over it writes the DID document — the
/// record whose BEP44 signature a resolver verifies against the public key
/// encoded in the DID string (§9.6.1). An action is reserved to `#active` when
/// it creates authority no existing delegation confers; root UCAN issuance is
/// that action, and no resource token names it, which is why `prf` rather than
/// this list is what
/// [`enforce_ucan_category_a`](crate::crypto::ucan) reads for it.
///
/// The list below enumerates the resource types that satisfy the first
/// criterion today; it is not the criterion. A resource type this list omits
/// is still Category A when it names a DID-document write, and the protocol
/// adds it here when the protocol defines it.
///
/// **One entry satisfies neither criterion.** `identity` names no DID-document
/// field and creates no authority. It is in the list because this file has
/// carried it since before ADR-039 stated the criteria, and removing it would
/// admit `#agent` on a resource no one has decided an agent may sign. Spec
/// §4.9.1 records the same carve-out, and
/// `.docs/specs/00-open-questions.md` carries the question of which criterion
/// admits it or whether it leaves the set. A reader must not infer from this
/// list that every entry writes the DID document.
///
/// **What a Category B verdict does not say.** Category A and Category B
/// partition which of the two — the protocol or the DID's owner — writes an
/// action's signing-key rule. Category C is a separate axis: a context
/// restricts what an agent may do inside it whatever this list says (§4.9.3),
/// so a resource type absent from this list is Category B and may still be
/// forbidden by the context the action runs in.
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

/// Returns the Category A resource types — the resource types the agent key
/// (`#agent`) MUST NOT sign.
///
/// `CATEGORY_A_RESOURCES` states the membership criterion these entries
/// satisfy. Exposed for conformance testing against mirror implementations.
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

/// The Category A resource types ADR-039 reserves to the Identity Key (`#0`).
///
/// **The criterion** (spec §4.9.1): a resource type belongs here when ADR-039
/// names `#0` as the key that performs the action — the three bullets that
/// read "requires `#0`" cover DID document updates (add/remove keys, change
/// services, alter relays), pre-rotation commitments, and identity migration.
/// The entries below are the resource tokens that name those writes; they are
/// evidence that an action is a DID-document write, not the test for whether
/// it is one.
///
/// **Why this set matters to a UCAN verifier.** [`scp_did::SigningKeyId`]
/// admits `#active` and `#agent` and nothing else, so `#0` never signs a UCAN.
/// A UCAN that grants a capability over one of these resource types therefore
/// conveys authority no key on the token can hold, whatever key signed it.
/// Authority for a DID-document write comes from the `#0` signature on the
/// published document (§9.6.1, §9.7.4), never from a capability token.
///
/// **Two Category A resource types are absent, each for its own reason.**
///
/// `identity` is absent because ADR-039 names no key reservation for a resource
/// token spelled `identity`. Reserving it to `#0` on the strength of its name
/// would decide a question ADR-039 left open, so a verifier admits `#active` on
/// it until ADR-039 states the reservation.
///
/// `service` is absent because two namespaces spell it the same way and this
/// set cannot tell them apart. A context declares custom ceiling entries under
/// the grammar `{resource}:{action}` where each segment matches `[a-z0-9-]+`
/// and the entry names no built-in (§5.3.1.1), and `service:read` satisfies
/// that grammar, so a context may put it in its own ceiling and mean its own
/// service registry by it. `service` is the only one of ADR-039's seven
/// DID-document resource tokens the grammar admits — the other six carry an
/// underscore, which the grammar forbids in a custom entry. Reserving `service`
/// to `#0` would therefore reject a capability a context legitimately declared,
/// so a verifier admits `#active` on it, exactly as it does on `origin/main`.
/// Rule 1 still rejects an `#agent` signature over it. `.docs/specs/00-open-questions.md`
/// records which namespace owns the token.
///
/// Neither absence widens what a UCAN can do to a DID document: authority for a
/// DID-document write comes from the `#0` signature on the published document,
/// and a capability token conveys none of it whatever this set says.
const IDENTITY_KEY_RESERVED_RESOURCES: &[&str] = &[
    "did_document",
    "verification_method",
    "key_management",
    "pre_rotation",
    "relay_config",
    "did_migration",
];

/// Returns the Category A resource types reserved to the Identity Key (`#0`).
///
/// `IDENTITY_KEY_RESERVED_RESOURCES` states the membership criterion these
/// entries satisfy. Exposed for conformance testing against mirror
/// implementations.
///
/// # Examples
///
/// ```
/// use scp_protocol::trust::custody_violation::identity_key_reserved_resources;
///
/// let resources = identity_key_reserved_resources();
/// assert!(resources.contains(&"did_document"));
/// assert!(!resources.contains(&"messages"));
/// ```
#[must_use]
pub const fn identity_key_reserved_resources() -> &'static [&'static str] {
    IDENTITY_KEY_RESERVED_RESOURCES
}

/// Reports whether ADR-039 reserves this UCAN capability resource type to the
/// Identity Key (`#0`).
///
/// A verifier rejects a capability token granting such a resource whatever key
/// signed the token, because `#0` never signs a UCAN (§4.9.1 rule 2).
///
/// **The decision reads the resource segment and ignores the action segment**,
/// so this function reports `true` for `did_document:read` as well as for
/// `did_document:update`, while §4.9.1's criterion names a DID-document
/// *write*. Rejecting the read spelling rejects nothing a context can grant:
/// each of the six entries carries an underscore, `is_kebab_token` in
/// [`crate::context::roles`] forbids an underscore in a custom ceiling entry
/// (§5.3.1.1), and none of the six is a built-in capability, so no context
/// ceiling admits `{entry}:{any action}` and step 8 of §7.2.1 rejects such a
/// token even when this rule passes it. Reading the action segment instead
/// would add a parser whose only effect is to decide which of two errors an
/// unreachable token reports. The two Category A resource tokens the kebab
/// grammar does admit, `service` and `identity`, are exactly the two this set
/// omits — see [`IDENTITY_KEY_RESERVED_RESOURCES`].
///
/// **Visibility.** The predicate is `pub(crate)` because the only caller is
/// `enforce_ucan_category_a` in [`crate::crypto::ucan`], and no FFI bridge
/// exports it. A mirror implementation reads the same set through the public
/// [`identity_key_reserved_resources`] and applies `contains` itself, so
/// narrowing the visibility withholds nothing a conformance test needs.
///
/// # Examples
///
/// ```
/// use scp_protocol::trust::custody_violation::identity_key_reserved_resources;
///
/// let reserved = identity_key_reserved_resources();
/// assert!(reserved.contains(&"pre_rotation"));
/// assert!(!reserved.contains(&"messages"));
/// // `identity` is Category A, and ADR-039 names no key reservation for it.
/// assert!(!reserved.contains(&"identity"));
/// // `service` is Category A, and a context may also declare it as a custom
/// // ceiling entry, so a verifier admits `#active` on it.
/// assert!(!reserved.contains(&"service"));
/// ```
#[must_use]
pub(crate) fn requires_identity_key(resource: &str) -> bool {
    IDENTITY_KEY_RESERVED_RESOURCES.contains(&resource)
}

/// Classifies an action by its UCAN capability resource type.
///
/// Returns [`ActionCategory::CategoryA`] if the resource type names a write to
/// the DID document, [`ActionCategory::CategoryB`] otherwise. A
/// [`ActionCategory::CategoryB`] verdict states that the DID's owner writes
/// the signing-key rule for the action; it does not state that any context
/// admits the action, which Category C decides on its own axis (§4.9.3).
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
