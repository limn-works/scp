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
//! - [`VerifiedCustodyViolation`] — A violation record whose verifier signature
//!   this process checked.
//! - [`CounterAttestation`] — Counter-evidence for reputation restoration.
//! - [`VerifiedCounterAttestation`] — A counter-attestation whose subject
//!   signature this process checked.
//! - [`CustodyViolationError`] — Validation errors for custody violation types.
//! - [`CustodyViolationResult`] — Result of a Category A enforcement check.
//! - [`CategoryARejection`] — What a verification point returns when it rejects
//!   a Category A action, carrying the record ADR-039 layer 3 requires it to log.
//! - [`ViolationStore`] — Trait for custody violation storage (append-only).
//! - [`InMemoryViolationStore`] — In-memory implementation for testing.
//!
//! # Signature verification
//!
//! [`ScpCustodyViolationAttestation`] and [`CounterAttestation`] each carry an
//! Ed25519 signature over a §9.5.1 canonical hash under its own domain
//! separator ([`CUSTODY_VIOLATION_DOMAIN`], [`COUNTER_ATTESTATION_DOMAIN`]).
//! Spec section §9.5.2 of `.docs/specs/09-security-model.md` fixes both field
//! layouts, spec section §9.18.2 registers both separators, and spec section
//! §25.25 of `.docs/specs/25-test-vectors.md` pins one known-answer preimage,
//! hash, and signature for each (Vector 38 and Vector 39). Each hash covers
//! every field of its record except that record's own signature.
//!
//! A caller resolves a signer's Ed25519 public key from a DID document and calls
//! [`VerifiedCustodyViolation::verify`] or [`VerifiedCounterAttestation::verify`].
//! Both constructors perform no DID resolution and no clock read, so both stay
//! wasm-safe and each caller decides which key it trusts. Only those two
//! constructors produce the two verified types, and [`ViolationStore`] accepts
//! nothing else, so a store cannot hold a record whose signature no party
//! checked.
//!
//! [`ScpCustodyViolationAttestation::validate_field_shape`] and
//! [`CounterAttestation::validate_field_shape`] check field shape and establish
//! nothing about who signed. Their names say so, and their return type is not a
//! verified record, so a caller cannot mistake shape validation for
//! authenticity.
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
//! See ADR-039, shared-DID human-agent identity model, in
//! `.docs/adrs/phase-1.md`, and spec section §9.5.2 of
//! `.docs/specs/09-security-model.md` for both signing-preimage field tables.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use scp_crypto::verify_ed25519_signature;
use scp_did::{DID, SigningKeyId};

use crate::crypto::canonical::{CanonicalField, canonical_hash};

// ---------------------------------------------------------------------------
// Domain separators (§9.5.1 canonical hash construction, §9.18.2 registry)
// ---------------------------------------------------------------------------

/// Domain separator for the [`ScpCustodyViolationAttestation`] signing preimage.
///
/// Spec section §9.5.2 of `.docs/specs/09-security-model.md` lists the seven
/// preimage fields this separator prefixes, and spec section §9.18.2 registers
/// `"SCP-CUSTODY-VIOLATION-V1:"` itself. ADR-039, shared-DID human-agent
/// identity model (`.docs/adrs/phase-1.md`), defines a custody-violation record
/// at enforcement-stack layer 4.
///
/// Changing any field's encoding, adding a field, or removing a field requires
/// a `V2` separator, because §9.5.1 ties one separator to one field layout.
pub const CUSTODY_VIOLATION_DOMAIN: &str = "SCP-CUSTODY-VIOLATION-V1:";

/// Domain separator for the [`CounterAttestation`] signing preimage.
///
/// Spec section §9.5.2 of `.docs/specs/09-security-model.md` lists the four
/// preimage fields this separator prefixes, and spec section §9.18.2 registers
/// `"SCP-COUNTER-ATTESTATION-V1:"` itself. ADR-039, shared-DID human-agent
/// identity model (`.docs/adrs/phase-1.md`), acceptance criterion 18 defines a
/// counter-attestation.
///
/// A separator distinct from [`CUSTODY_VIOLATION_DOMAIN`] stops one record
/// type's signature from verifying over another record type's fields.
pub const COUNTER_ATTESTATION_DOMAIN: &str = "SCP-COUNTER-ATTESTATION-V1:";

/// Preimage discriminator for [`CustodyViolationType::CategoryAViolation`]
/// (spec section §9.5.2, field 3).
const VIOLATION_TAG_CATEGORY_A: u8 = 0x00;

/// Preimage discriminator for [`CustodyViolationType::AttestationMismatch`]
/// (spec section §9.5.2, field 3).
const VIOLATION_TAG_ATTESTATION_MISMATCH: u8 = 0x01;

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
    /// Ed25519 signature by `verifier_did` over
    /// [`signing_hash`](ScpCustodyViolationAttestation::signing_hash), a §9.5.1
    /// canonical hash under [`CUSTODY_VIOLATION_DOMAIN`] that covers every other
    /// field of this record.
    ///
    /// [`VerifiedCustodyViolation::verify`] rebuilds that hash and checks
    /// `verifier_signature` against a caller-supplied Ed25519 public key. A
    /// caller that resolves that key from `verifier_did`'s current DID document
    /// and runs that check establishes that whoever holds `verifier_did`'s key
    /// wrote exactly these bytes. That check establishes nothing about whether a
    /// recorded violation occurred, because `verifier_did` alone chose what to
    /// write.
    ///
    /// [`validate_field_shape`](ScpCustodyViolationAttestation::validate_field_shape)
    /// checks only that `verifier_signature` is non-empty, so a caller that skips
    /// [`VerifiedCustodyViolation::verify`] learns nothing about who wrote a
    /// record.
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

    /// A §9.5.1 canonical signing preimage could not be encoded.
    ///
    /// [`crate::crypto::canonical::canonical_hash`] rejects a variable-length
    /// field longer than `u32::MAX` bytes, and that rejection is this variant's
    /// only source. Spec section §9.10.3 bounds a protocol message to 256 KB, so
    /// a record reaching that ceiling did not come from a conformant sender.
    #[error("canonical signing preimage encoding failed: {reason}")]
    CanonicalEncodingFailed {
        /// What [`crate::crypto::canonical::canonical_hash`] reported.
        reason: String,
    },

    /// An Ed25519 signature did not verify against a supplied public key.
    ///
    /// One record's bytes differ from bytes its signer signed, a supplied key is
    /// not a key that signed, or key bytes or signature bytes are malformed.
    /// `scp_crypto::verify_ed25519_signature` reports which case applies.
    #[error("signature verification failed: {reason}")]
    SignatureVerificationFailed {
        /// What `scp_crypto::verify_ed25519_signature` reported.
        reason: String,
    },

    /// A counter-attestation's `violation_reference` does not equal the signing
    /// hash of the violation record a caller offered it against.
    ///
    /// Spec section §9.5.2 of `.docs/specs/09-security-model.md` derives
    /// `violation_reference` from that signing hash, so a mismatch means this
    /// counter-claim answers a different record, or answers no record.
    #[error(
        "counter-attestation references a different violation record: \
         expected {expected}, found {found}"
    )]
    ViolationReferenceMismatch {
        /// Lowercase hex of the signing hash of the offered violation record.
        expected: String,
        /// Lowercase hex of the reference the counter-attestation carries.
        found: String,
    },

    /// A counter-attestation names a different subject than the violation record
    /// a caller offered it against.
    ///
    /// Spec section §9.5.2 of `.docs/specs/09-security-model.md` requires both
    /// `subject_did` values to match, so that one subject cannot contest a record
    /// naming another subject.
    #[error(
        "counter-attestation subject {counter_subject} does not match violation subject {violation_subject}"
    )]
    SubjectMismatch {
        /// The `subject_did` the counter-attestation carries.
        counter_subject: String,
        /// The `subject_did` the violation record carries.
        violation_subject: String,
    },
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

    /// Returns fields 3 through 6 of a [`ScpCustodyViolationAttestation`]
    /// signing preimage: a one-byte variant discriminator followed by this
    /// variant's three payload fields, each length-prefixed per §9.5.1.
    ///
    /// Spec section §9.5.2 of `.docs/specs/09-security-model.md` fixes both
    /// discriminator values and both field orders. That discriminator stops a
    /// [`CategoryAViolation`](Self::CategoryAViolation) whose three fields carry
    /// the same bytes as an [`AttestationMismatch`](Self::AttestationMismatch)
    /// from hashing to one value, which would let one variant's signature verify
    /// over another variant's fields.
    fn canonical_fields(&self) -> [CanonicalField<'_>; 4] {
        match self {
            Self::CategoryAViolation {
                action,
                signer_key_id,
                signature_evidence,
            } => [
                CanonicalField::U8(VIOLATION_TAG_CATEGORY_A),
                CanonicalField::VarBytes(action.as_bytes()),
                CanonicalField::VarBytes(signer_key_id.as_bytes()),
                CanonicalField::VarBytes(signature_evidence),
            ],
            Self::AttestationMismatch {
                claimed_custody,
                observed_behavior,
                attestation_evidence,
            } => [
                CanonicalField::U8(VIOLATION_TAG_ATTESTATION_MISMATCH),
                CanonicalField::VarBytes(claimed_custody.as_bytes()),
                CanonicalField::VarBytes(observed_behavior.as_bytes()),
                CanonicalField::VarBytes(attestation_evidence),
            ],
        }
    }
}

impl ScpCustodyViolationAttestation {
    /// Checks that every field of this record has a well-formed shape, and
    /// establishes nothing about who signed it.
    ///
    /// This method reads no key, recomputes no hash, and checks no signature. A
    /// caller that wants to know who wrote a record calls
    /// [`VerifiedCustodyViolation::verify`] with a key it resolved from
    /// `verifier_did`'s DID document, and [`ViolationStore`] accepts only the
    /// [`VerifiedCustodyViolation`] that constructor returns.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyViolationError`] if the violation evidence is invalid
    /// or the verifier signature is empty.
    pub fn validate_field_shape(&self) -> Result<(), CustodyViolationError> {
        self.violation.validate()?;
        if self.verifier_signature.is_empty() {
            return Err(CustodyViolationError::EmptyVerifierSignature);
        }
        Ok(())
    }

    /// Creates a new custody violation attestation, checking every field's shape.
    ///
    /// Shape is all this constructor checks. It performs no signature
    /// verification, so holding the value it returns establishes nothing about
    /// who signed the record.
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

    /// Returns the 32-byte §9.5.1 canonical signing hash for this record:
    /// `SHA-256(CUSTODY_VIOLATION_DOMAIN || fields 1..7)`.
    ///
    /// Spec section §9.5.2 of `.docs/specs/09-security-model.md` fixes all seven
    /// fields and their order: `subject_did`, `timestamp`, a one-byte variant
    /// discriminator, `violation`'s three payload fields, and `verifier_did`.
    /// This hash covers every field of this record except `verifier_signature`,
    /// so a party who alters `subject_did`, `timestamp`, any component of
    /// `violation`, or `verifier_did` moves this hash and invalidates a
    /// signature taken over an earlier value.
    ///
    /// A signer signs these 32 bytes and nothing else. ADR-039, shared-DID
    /// human-agent identity model (`.docs/adrs/phase-1.md`), enforcement-stack
    /// layer 4 names a detecting verifier as that signer.
    ///
    /// Spec section §9.5.2 also derives a [`CounterAttestation`]'s
    /// `violation_reference` from this same 32-byte value, so a subject that
    /// contests this record carries these bytes and a verifier recomputes them.
    /// [`CounterAttestation::referencing`] computes that field from a record
    /// rather than accepting an identifier a caller invented, and
    /// [`VerifiedCounterAttestation::answers`] rechecks it.
    ///
    /// §25.25 Vector 38 of `.docs/specs/25-test-vectors.md` pins one
    /// known-answer preimage and its hash.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyViolationError::CanonicalEncodingFailed`] when a
    /// variable-length field exceeds the `u32::MAX` length-prefix ceiling that
    /// §9.5.1 imposes.
    pub fn signing_hash(&self) -> Result<[u8; 32], CustodyViolationError> {
        let mut fields = Vec::with_capacity(7);
        fields.push(CanonicalField::VarBytes(self.subject_did.0.as_bytes()));
        fields.push(CanonicalField::U64(self.timestamp));
        fields.extend(self.violation.canonical_fields());
        fields.push(CanonicalField::VarBytes(self.verifier_did.0.as_bytes()));

        canonical_hash(CUSTODY_VIOLATION_DOMAIN, &fields).map_err(|e| {
            CustodyViolationError::CanonicalEncodingFailed {
                reason: e.to_string(),
            }
        })
    }

    /// Verifies `verifier_signature` against `verifier_public_key`, using one
    /// primitive that
    /// [`crate::identity::attestation::IdentityLinkAttestation::verify_signature`]
    /// also uses: `scp_crypto::verify_ed25519_signature`, which calls
    /// `ed25519_dalek::VerifyingKey::verify_strict`.
    ///
    /// Module-private on purpose. [`VerifiedCustodyViolation::verify`] is the
    /// only public entry point, so a caller that runs this check receives a
    /// [`VerifiedCustodyViolation`] and cannot hold a bare
    /// `ScpCustodyViolationAttestation` that it believes some party
    /// authenticated.
    fn verify_verifier_signature(
        &self,
        verifier_public_key: &[u8],
    ) -> Result<(), CustodyViolationError> {
        let hash = self.signing_hash()?;
        verify_ed25519_signature(verifier_public_key, &hash, &self.verifier_signature)
            .map_err(|reason| CustodyViolationError::SignatureVerificationFailed { reason })
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
// VerifiedCustodyViolation (issue #2335 finding 11)
// ---------------------------------------------------------------------------

/// A [`ScpCustodyViolationAttestation`] whose `verifier_signature` this process
/// checked against an Ed25519 public key the caller supplied.
///
/// [`verify`](Self::verify) is the only constructor, so a value of this type
/// carries a fact a bare [`ScpCustodyViolationAttestation`] never carries:
/// whoever holds the key that caller supplied signed exactly the field bytes
/// this record now carries. [`ViolationStore::log_violation`] accepts this type
/// and rejects the bare record, so an append-only store of permanent accusations
/// holds nothing that no party authenticated.
///
/// This type implements `Serialize` and does not implement `Deserialize`, so a
/// verified record cannot arrive from the wire: a process that reads a record
/// off the wire deserializes [`ScpCustodyViolationAttestation`] and runs
/// [`verify`](Self::verify) itself.
///
/// Holding this type establishes nothing about whether the recorded violation
/// occurred: ADR-039, shared-DID human-agent identity model
/// (`.docs/adrs/phase-1.md`), enforcement-stack layer 4 lets one verifier write
/// a record about a subject who never consented, and that verifier alone chose
/// what to write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedCustodyViolation(ScpCustodyViolationAttestation);

impl VerifiedCustodyViolation {
    /// Checks `record`'s field shape, then checks `record.verifier_signature`
    /// against `verifier_public_key` over the §9.5.1 canonical hash
    /// [`ScpCustodyViolationAttestation::signing_hash`] builds.
    ///
    /// A caller resolves `verifier_public_key` from `record.verifier_did`'s
    /// current DID document. ADR-039, shared-DID human-agent identity model
    /// (`.docs/adrs/phase-1.md`), names `#active` and `#agent` as both
    /// verification methods a verifier may sign with. This constructor performs
    /// no DID resolution and no clock read, so it stays wasm-safe and each caller
    /// chooses which key it trusts.
    ///
    /// # Errors
    ///
    /// Returns the [`CustodyViolationError`] that
    /// [`ScpCustodyViolationAttestation::validate_field_shape`] reports for a
    /// malformed field, [`CustodyViolationError::CanonicalEncodingFailed`] when
    /// the preimage cannot be encoded, and
    /// [`CustodyViolationError::SignatureVerificationFailed`] when
    /// `verifier_signature` does not verify against `verifier_public_key`.
    pub fn verify(
        record: ScpCustodyViolationAttestation,
        verifier_public_key: &[u8],
    ) -> Result<Self, CustodyViolationError> {
        record.validate_field_shape()?;
        record.verify_verifier_signature(verifier_public_key)?;
        Ok(Self(record))
    }

    /// Borrows the record this value verified.
    #[must_use]
    pub const fn record(&self) -> &ScpCustodyViolationAttestation {
        &self.0
    }

    /// Returns the record this value verified, dropping the verified marker.
    #[must_use]
    pub fn into_record(self) -> ScpCustodyViolationAttestation {
        self.0
    }

    /// Returns the 32-byte reference a [`CounterAttestation`] carries to name
    /// this record, per spec section §9.5.2's derivation rule.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyViolationError::CanonicalEncodingFailed`] when
    /// [`ScpCustodyViolationAttestation::signing_hash`] cannot encode a preimage.
    pub fn reference(&self) -> Result<[u8; 32], CustodyViolationError> {
        self.0.signing_hash()
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
    /// The 32-byte identifier of the violation record this counter-claim
    /// contests.
    ///
    /// Spec section §9.5.2 of `.docs/specs/09-security-model.md` derives this
    /// field: it equals
    /// [`ScpCustodyViolationAttestation::signing_hash`] of the contested record,
    /// which is `SHA-256(CUSTODY_VIOLATION_DOMAIN || fields 1..7)`. Any other
    /// 32-byte value names no record.
    ///
    /// [`referencing`](CounterAttestation::referencing) computes this field from
    /// a violation record rather than accepting an identifier a caller invented,
    /// and [`VerifiedCounterAttestation::answers`] recomputes it from the record
    /// a verifier holds and rejects a mismatch. Those two checks are why this
    /// field is 32 bytes rather than a free-form string: two verifiers reach one
    /// answer to "does this counter-claim answer this record".
    pub violation_reference: [u8; 32],
    /// Human-readable explanation of the counter-claim.
    pub explanation: String,
    /// Unix timestamp (seconds) when the counter-attestation was published.
    pub timestamp: u64,
    /// Ed25519 signature over
    /// [`signing_hash`](CounterAttestation::signing_hash), a §9.5.1 canonical
    /// hash under [`COUNTER_ATTESTATION_DOMAIN`] that covers every other field
    /// of this record.
    ///
    /// ADR-039, shared-DID human-agent identity model (`.docs/adrs/phase-1.md`),
    /// acceptance criterion 18 assigns a counter-claim signature to `#active`
    /// rather than `#agent`. This struct carries no `signing_key_id` field,
    /// because a subject that names its own fragment inside a record it also
    /// signs can name `#active` while signing with `#agent`. Each caller
    /// enforces that assignment instead: a caller that resolves `#active` from
    /// `subject_did`'s current DID document and passes that key to
    /// [`verify_signature`](CounterAttestation::verify_signature) establishes
    /// that whoever holds `#active` signed this counter-claim, and a signature
    /// that only `#agent` produced then fails. A caller that passes `#agent`
    /// establishes agent authorization and establishes nothing about human
    /// involvement.
    ///
    /// [`validate_field_shape`](CounterAttestation::validate_field_shape) checks
    /// only that `signature` is non-empty.
    pub signature: Vec<u8>,
}

impl CounterAttestation {
    /// Checks that every field of this record has a well-formed shape, and
    /// establishes nothing about who signed it.
    ///
    /// This method reads no key, recomputes no hash, and checks no signature. A
    /// caller that wants to know who wrote a counter-claim calls
    /// [`VerifiedCounterAttestation::verify`] with a key it resolved from
    /// `subject_did`'s DID document. This method also cannot tell whether
    /// `violation_reference` names a record that exists; only
    /// [`VerifiedCounterAttestation::answers`] answers that, and it needs the
    /// record.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyViolationError`] if `explanation` or `signature` is
    /// empty.
    pub const fn validate_field_shape(&self) -> Result<(), CustodyViolationError> {
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

    /// Creates a counter-attestation against `violation`, deriving both
    /// `subject_did` and `violation_reference` from that record.
    ///
    /// This is the only constructor, and it takes a violation record rather than
    /// a caller-chosen reference, so an author cannot publish a counter-claim
    /// against a record it does not hold. Spec section §9.5.2 of
    /// `.docs/specs/09-security-model.md` states that derivation:
    /// `violation_reference` equals
    /// [`ScpCustodyViolationAttestation::signing_hash`] of `violation`, and both
    /// records name one `subject_did`.
    ///
    /// `signature` is an Ed25519 signature by `violation.subject_did`'s `#active`
    /// verification method over [`signing_hash`](Self::signing_hash) of the value
    /// this constructor returns. An author builds the value, reads that hash,
    /// signs it, and writes the result back into `signature`; the round-trip in
    /// this module's tests shows that sequence.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyViolationError::CanonicalEncodingFailed`] when
    /// `violation`'s preimage cannot be encoded, and
    /// [`CustodyViolationError::EmptyField`] when `explanation` or `signature` is
    /// empty.
    pub fn referencing(
        violation: &ScpCustodyViolationAttestation,
        explanation: String,
        timestamp: u64,
        signature: Vec<u8>,
    ) -> Result<Self, CustodyViolationError> {
        let counter = Self {
            subject_did: violation.subject_did.clone(),
            violation_reference: violation.signing_hash()?,
            explanation,
            timestamp,
            signature,
        };
        counter.validate_field_shape()?;
        Ok(counter)
    }

    /// Returns the 32-byte §9.5.1 canonical signing hash for this record:
    /// `SHA-256(COUNTER_ATTESTATION_DOMAIN || fields 1..4)`.
    ///
    /// Spec section §9.5.2 of `.docs/specs/09-security-model.md` fixes all four
    /// fields and their order: `subject_did`, `violation_reference`,
    /// `explanation`, `timestamp`. This hash covers every field of this record
    /// except `signature`, so a party who alters `subject_did`, retargets
    /// `violation_reference` at a different violation, rewrites `explanation`,
    /// or backdates `timestamp` moves this hash and invalidates a signature
    /// taken over an earlier value.
    ///
    /// A signer signs these 32 bytes and nothing else. §25.25 Vector 39 of
    /// `.docs/specs/25-test-vectors.md` pins one known-answer preimage and its
    /// hash.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyViolationError::CanonicalEncodingFailed`] when a
    /// variable-length field exceeds the `u32::MAX` length-prefix ceiling that
    /// §9.5.1 imposes.
    pub fn signing_hash(&self) -> Result<[u8; 32], CustodyViolationError> {
        canonical_hash(
            COUNTER_ATTESTATION_DOMAIN,
            &[
                CanonicalField::VarBytes(self.subject_did.0.as_bytes()),
                CanonicalField::Fixed32(&self.violation_reference),
                CanonicalField::VarBytes(self.explanation.as_bytes()),
                CanonicalField::U64(self.timestamp),
            ],
        )
        .map_err(|e| CustodyViolationError::CanonicalEncodingFailed {
            reason: e.to_string(),
        })
    }

    /// Verifies `signature` against `subject_public_key`, using one primitive
    /// that
    /// [`crate::identity::attestation::IdentityLinkAttestation::verify_signature`]
    /// also uses: `scp_crypto::verify_ed25519_signature`, which calls
    /// `ed25519_dalek::VerifyingKey::verify_strict`.
    ///
    /// Module-private on purpose. [`VerifiedCounterAttestation::verify`] is the
    /// only public entry point, so a caller that runs this check receives a
    /// [`VerifiedCounterAttestation`] and cannot hold a bare
    /// `CounterAttestation` that it believes some party authenticated.
    fn verify_signature(&self, subject_public_key: &[u8]) -> Result<(), CustodyViolationError> {
        let hash = self.signing_hash()?;
        verify_ed25519_signature(subject_public_key, &hash, &self.signature)
            .map_err(|reason| CustodyViolationError::SignatureVerificationFailed { reason })
    }
}

// ---------------------------------------------------------------------------
// VerifiedCounterAttestation (issue #2335 finding 11)
// ---------------------------------------------------------------------------

/// A [`CounterAttestation`] whose `signature` this process checked against an
/// Ed25519 public key the caller supplied.
///
/// [`verify`](Self::verify) is the only constructor, so a value of this type
/// carries a fact a bare [`CounterAttestation`] never carries: whoever holds the
/// key that caller supplied signed exactly the field bytes this counter-claim
/// now carries. [`ViolationStore::log_counter_attestation`] accepts this type
/// and rejects the bare record.
///
/// This type implements `Serialize` and does not implement `Deserialize`, so a
/// verified counter-claim cannot arrive from the wire.
///
/// ADR-039, shared-DID human-agent identity model (`.docs/adrs/phase-1.md`),
/// acceptance criterion 18 assigns a counter-claim signature to `#active`. This
/// type records that a signature verified, not which verification method the
/// caller resolved, so a caller that wants criterion 18 resolves `#active` and
/// passes only that key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedCounterAttestation(CounterAttestation);

impl VerifiedCounterAttestation {
    /// Checks `record`'s field shape, then checks `record.signature` against
    /// `subject_public_key` over the §9.5.1 canonical hash
    /// [`CounterAttestation::signing_hash`] builds.
    ///
    /// This constructor performs no DID resolution and no clock read, so it
    /// stays wasm-safe. It does not check that `record.violation_reference`
    /// names a record that exists, because a counter-claim reaches a verifier
    /// that may not hold the contested record; [`answers`](Self::answers) makes
    /// that check once a verifier holds it.
    ///
    /// # Errors
    ///
    /// Returns the [`CustodyViolationError`] that
    /// [`CounterAttestation::validate_field_shape`] reports for a malformed
    /// field, [`CustodyViolationError::CanonicalEncodingFailed`] when the
    /// preimage cannot be encoded, and
    /// [`CustodyViolationError::SignatureVerificationFailed`] when `signature`
    /// does not verify against `subject_public_key`.
    pub fn verify(
        record: CounterAttestation,
        subject_public_key: &[u8],
    ) -> Result<Self, CustodyViolationError> {
        record.validate_field_shape()?;
        record.verify_signature(subject_public_key)?;
        Ok(Self(record))
    }

    /// Borrows the record this value verified.
    #[must_use]
    pub const fn record(&self) -> &CounterAttestation {
        &self.0
    }

    /// Returns the record this value verified, dropping the verified marker.
    #[must_use]
    pub fn into_record(self) -> CounterAttestation {
        self.0
    }

    /// Checks that this counter-claim answers `violation`, running both checks
    /// spec section §9.5.2 of `.docs/specs/09-security-model.md` requires:
    /// `violation_reference` equals `violation`'s signing hash, and both records
    /// name one `subject_did`.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyViolationError::ViolationReferenceMismatch`] when this
    /// counter-claim references a different record,
    /// [`CustodyViolationError::SubjectMismatch`] when the two records name
    /// different subjects, and
    /// [`CustodyViolationError::CanonicalEncodingFailed`] when `violation`'s
    /// preimage cannot be encoded.
    pub fn answers(
        &self,
        violation: &VerifiedCustodyViolation,
    ) -> Result<(), CustodyViolationError> {
        let expected = violation.reference()?;
        if self.0.violation_reference != expected {
            return Err(CustodyViolationError::ViolationReferenceMismatch {
                expected: hex::encode(expected),
                found: hex::encode(self.0.violation_reference),
            });
        }
        if self.0.subject_did != violation.record().subject_did {
            return Err(CustodyViolationError::SubjectMismatch {
                counter_subject: self.0.subject_did.0.clone(),
                violation_subject: violation.record().subject_did.0.clone(),
            });
        }
        Ok(())
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
        value
            .validate_field_shape()
            .map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl<'de> Deserialize<'de> for CounterAttestation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            subject_did: DID,
            violation_reference: [u8; 32],
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
        value
            .validate_field_shape()
            .map_err(serde::de::Error::custom)?;
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

    /// The signature bytes the verification point observed on the rejected
    /// action — the `evidence_signature` argument
    /// [`enforce_category_a`] received, carried through unchanged.
    ///
    /// [`into_category_a_violation`](Self::into_category_a_violation) moves
    /// these bytes into the `signature_evidence` field of
    /// [`CustodyViolationType::CategoryAViolation`], so a caller that logs the
    /// violation records the signature it actually saw rather than a value it
    /// invented.
    pub signature_evidence: Vec<u8>,
}

impl CustodyViolationResult {
    /// Converts this enforcement rejection into the
    /// [`CustodyViolationType::CategoryAViolation`] a caller logs, carrying the
    /// observed [`signature_evidence`](Self::signature_evidence) through as the
    /// violation's cryptographic evidence.
    ///
    /// ADR-039, shared-DID human-agent identity model (`.docs/adrs/phase-1.md`),
    /// enforcement-stack layer 3 requires a verification point to both reject a
    /// Category A action signed by `#agent` and record it; this method produces
    /// the record from the rejection, so the two cannot disagree about which
    /// signature was seen. `CategoryARejection::from` calls this method, which
    /// is how both shipped verification points — `enforce_inner_envelope_category_a`
    /// and
    /// [`enforce_sender_key_category_a`](crate::crypto::sender_keys::key_protocol_verify::enforce_sender_key_category_a)
    /// — hand a record to their callers.
    ///
    /// # Errors
    ///
    /// Returns the [`CustodyViolationError`] that
    /// [`CustodyViolationType::validate`] reports when `attempted_action` is
    /// empty, `signature_evidence` is empty, or `signing_key_id` is not
    /// [`SigningKeyId::Agent`].
    pub fn into_category_a_violation(self) -> Result<CustodyViolationType, CustodyViolationError> {
        let violation = CustodyViolationType::CategoryAViolation {
            action: self.attempted_action,
            signer_key_id: self.signing_key_id,
            signature_evidence: self.signature_evidence,
        };
        violation.validate()?;
        Ok(violation)
    }
}

// ---------------------------------------------------------------------------
// CategoryARejection (ADR-039 enforcement-stack layer 3)
// ---------------------------------------------------------------------------

/// What a verification point returns when it rejects a Category A action that
/// `#agent` signed.
///
/// ADR-039, shared-DID human-agent identity model (`.docs/adrs/phase-1.md`),
/// enforcement-stack layer 3 states that a conformant verifier both rejects such
/// an action and logs it as a custody violation. This type carries both halves:
/// `error_message` is the rejection a caller surfaces, and the
/// [`Recorded`](Self::Recorded) variant carries the
/// [`CustodyViolationType::CategoryAViolation`] a caller logs, holding the
/// signature bytes that verification point observed.
///
/// The two variants split on one condition: whether the observed evidence forms
/// a conformant record. A verification point that observed no signature bytes
/// still rejects the action, and this type reports why no record accompanies
/// that rejection rather than inventing evidence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CategoryARejection {
    /// The verification point rejected the action and built the record ADR-039
    /// layer 3 requires it to log.
    #[error("{error_message}")]
    Recorded {
        /// Human-readable description of the rejected action.
        error_message: String,
        /// The DID whose `#agent` key signed the rejected action.
        violator_did: String,
        /// The record a caller logs, carrying the observed signature bytes as
        /// `signature_evidence`.
        violation: CustodyViolationType,
    },

    /// The verification point rejected the action, and the evidence it observed
    /// does not form a conformant record.
    ///
    /// [`CustodyViolationType::validate`] reports why. A verification point that
    /// saw an empty signature reaches this variant, and a caller that logs
    /// violations records nothing for this rejection rather than recording
    /// invented evidence.
    #[error("{error_message}; no conformant violation record: {reason}")]
    EvidenceUnusable {
        /// Human-readable description of the rejected action.
        error_message: String,
        /// The DID whose `#agent` key signed the rejected action.
        violator_did: String,
        /// What [`CustodyViolationType::validate`] reported.
        reason: CustodyViolationError,
    },
}

impl CategoryARejection {
    /// Returns the human-readable description of the rejected action.
    #[must_use]
    pub fn error_message(&self) -> &str {
        match self {
            Self::Recorded { error_message, .. } | Self::EvidenceUnusable { error_message, .. } => {
                error_message
            }
        }
    }

    /// Returns the DID whose `#agent` key signed the rejected action.
    #[must_use]
    pub fn violator_did(&self) -> &str {
        match self {
            Self::Recorded { violator_did, .. } | Self::EvidenceUnusable { violator_did, .. } => {
                violator_did
            }
        }
    }

    /// Borrows the record a caller logs, or returns `None` when the observed
    /// evidence does not form a conformant record.
    #[must_use]
    pub const fn recorded_violation(&self) -> Option<&CustodyViolationType> {
        match self {
            Self::Recorded { violation, .. } => Some(violation),
            Self::EvidenceUnusable { .. } => None,
        }
    }
}

impl From<CustodyViolationResult> for CategoryARejection {
    /// Moves the observed signature bytes out of a
    /// [`CustodyViolationResult`] and into the
    /// [`CustodyViolationType::CategoryAViolation`] a caller logs.
    fn from(result: CustodyViolationResult) -> Self {
        let error_message = result.error_message.clone();
        let violator_did = result.violator_did.clone();
        match result.into_category_a_violation() {
            Ok(violation) => Self::Recorded {
                error_message,
                violator_did,
                violation,
            },
            Err(reason) => Self::EvidenceUnusable {
                error_message,
                violator_did,
                reason,
            },
        }
    }
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
/// * `evidence_signature` — The signature bytes the verification point observed
///   on the action. A rejection carries these bytes through to
///   [`CustodyViolationResult::signature_evidence`], and
///   `CategoryARejection::from` moves them into the
///   [`CustodyViolationType::CategoryAViolation`] a caller logs, so a caller
///   records the signature it saw rather than a value it invented.
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
    evidence_signature: &[u8],
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
            signature_evidence: evidence_signature.to_vec(),
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
/// Both logging methods take a verified record, so an implementation stores
/// nothing whose signature no party checked. A caller that holds a bare
/// [`ScpCustodyViolationAttestation`] reaches these methods only by resolving a
/// key and calling [`VerifiedCustodyViolation::verify`].
///
/// See ADR-039 acceptance criteria 17-18.
pub trait ViolationStore {
    /// Log a custody violation attestation whose verifier signature a caller
    /// already checked.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyViolationError`] if an implementation rejects the
    /// record.
    fn log_violation(
        &mut self,
        attestation: VerifiedCustodyViolation,
    ) -> Result<(), CustodyViolationError>;

    /// Log a counter-attestation whose subject signature a caller already
    /// checked, against a previously recorded violation.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyViolationError`] if an implementation rejects the
    /// record.
    fn log_counter_attestation(
        &mut self,
        counter: VerifiedCounterAttestation,
    ) -> Result<(), CustodyViolationError>;

    /// Retrieve all violation attestations for a DID.
    ///
    /// Returns an empty vec if no violations have been recorded for the DID.
    fn get_violations_for_did(&self, did: &DID) -> Vec<&VerifiedCustodyViolation>;

    /// Retrieve all counter-attestations for a DID.
    ///
    /// Returns counter-attestations where `subject_did` matches the given DID.
    fn get_counter_attestations_for_did(&self, did: &DID) -> Vec<&VerifiedCounterAttestation>;
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
    violations: HashMap<DID, Vec<VerifiedCustodyViolation>>,

    /// Counter-attestations keyed by subject DID.
    counter_attestations: HashMap<DID, Vec<VerifiedCounterAttestation>>,
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
        attestation: VerifiedCustodyViolation,
    ) -> Result<(), CustodyViolationError> {
        let did = attestation.record().subject_did.clone();
        self.violations.entry(did).or_default().push(attestation);
        Ok(())
    }

    fn log_counter_attestation(
        &mut self,
        counter: VerifiedCounterAttestation,
    ) -> Result<(), CustodyViolationError> {
        let did = counter.record().subject_did.clone();
        self.counter_attestations
            .entry(did)
            .or_default()
            .push(counter);
        Ok(())
    }

    fn get_violations_for_did(&self, did: &DID) -> Vec<&VerifiedCustodyViolation> {
        self.violations
            .get(did)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    fn get_counter_attestations_for_did(&self, did: &DID) -> Vec<&VerifiedCounterAttestation> {
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

    /// Builds an unsigned violation record naming `subject`, for tests that need
    /// something to reference.
    fn sample_violation(subject: &str) -> ScpCustodyViolationAttestation {
        ScpCustodyViolationAttestation {
            subject_did: test_did(subject),
            timestamp: 1_700_000_000,
            violation: sample_category_a_violation(),
            verifier_signature: vec![0u8; 64],
            verifier_did: test_did("verifier"),
        }
    }

    #[test]
    fn counter_attestation_referencing_derives_subject_and_reference() {
        let violation = sample_violation("subject");
        let ca = CounterAttestation::referencing(
            &violation,
            "Key was rotated before the violation timestamp".to_string(),
            1_700_001_000,
            vec![0xAA, 0xBB, 0xCC],
        )
        .unwrap();

        assert_eq!(ca.subject_did, violation.subject_did);
        assert_eq!(ca.violation_reference, violation.signing_hash().unwrap());
        assert_eq!(ca.timestamp, 1_700_001_000);
    }

    /// Two violation records that differ in one recorded fact produce two
    /// references, so one counter-claim cannot answer both.
    #[test]
    fn counter_attestation_reference_separates_two_violations() {
        let first = sample_violation("subject");
        let mut second = first.clone();
        second.timestamp += 1;

        let counter_first =
            CounterAttestation::referencing(&first, "answer".to_string(), 1, vec![0x01]).unwrap();
        let counter_second =
            CounterAttestation::referencing(&second, "answer".to_string(), 1, vec![0x01]).unwrap();

        assert_ne!(
            counter_first.violation_reference,
            counter_second.violation_reference
        );
    }

    #[test]
    fn counter_attestation_rejects_empty_explanation() {
        let err = CounterAttestation::referencing(
            &sample_violation("subject"),
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
        let err = CounterAttestation::referencing(
            &sample_violation("subject"),
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
        let ca = CounterAttestation::referencing(
            &sample_violation("subject"),
            "Key was rotated before the violation timestamp".to_string(),
            1_700_001_000,
            vec![0xAA, 0xBB, 0xCC],
        )
        .unwrap();

        let json = serde_json::to_string(&ca).unwrap();
        let back: CounterAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(ca, back);
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
            "violation_reference": vec![0u8; 32],
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

    /// Builds a violation record naming `subject`, signs it with the verifier
    /// key, and returns the [`VerifiedCustodyViolation`] a store accepts.
    fn make_test_violation(subject: &str, action: &str) -> VerifiedCustodyViolation {
        let key = test_signing_key(21);
        let mut record = ScpCustodyViolationAttestation {
            subject_did: DID(subject.to_string()),
            timestamp: 1_700_000_000,
            violation: CustodyViolationType::CategoryAViolation {
                action: action.to_string(),
                signer_key_id: SigningKeyId::Agent,
                signature_evidence: vec![0xDE, 0xAD],
            },
            verifier_signature: vec![0u8; 64],
            verifier_did: DID("did:dht:verifier".to_string()),
        };
        record.verifier_signature = key
            .sign(&record.signing_hash().unwrap())
            .to_bytes()
            .to_vec();
        VerifiedCustodyViolation::verify(record, key.verifying_key().as_bytes()).unwrap()
    }

    /// Builds a counter-attestation against `violation`, signs it with the
    /// subject key, and returns the [`VerifiedCounterAttestation`] a store
    /// accepts.
    fn make_test_counter(violation: &VerifiedCustodyViolation) -> VerifiedCounterAttestation {
        let key = test_signing_key(22);
        let mut counter = CounterAttestation::referencing(
            violation.record(),
            "key rotated, incident resolved".to_string(),
            1_700_001_000,
            vec![0u8; 64],
        )
        .unwrap();
        counter.signature = key
            .sign(&counter.signing_hash().unwrap())
            .to_bytes()
            .to_vec();
        VerifiedCounterAttestation::verify(counter, key.verifying_key().as_bytes()).unwrap()
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
            &results[0].record().violation,
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

        let violation = make_test_violation("did:dht:alice", "did_document_update");
        let expected_reference = violation.reference().unwrap();
        let counter = make_test_counter(&violation);
        counter
            .answers(&violation)
            .expect("a counter-claim built from this record answers it");
        store.log_violation(violation).unwrap();
        store.log_counter_attestation(counter).unwrap();

        let alice_did = DID("did:dht:alice".to_string());
        let counters = store.get_counter_attestations_for_did(&alice_did);
        assert_eq!(counters.len(), 1);
        assert_eq!(counters[0].record().violation_reference, expected_reference);
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
            &violations[0].record().violation,
            CustodyViolationType::CategoryAViolation { action, .. }
                if action == "did_document_update"
        ));
        assert!(matches!(
            &violations[1].record().violation,
            CustodyViolationType::CategoryAViolation { action, .. }
                if action == "pre_rotation"
        ));
    }

    // -------------------------------------------------------------------
    // Signature verification (issue #2335 finding 11)
    //
    // Each verifier gets a sign-then-verify round trip, a wrong-key
    // rejection, and one tampered-field rejection per signed field.
    // -------------------------------------------------------------------

    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    /// Builds a deterministic Ed25519 signing key from a one-byte seed. Test
    /// code only: a production signer derives its key from `OsRng` through
    /// `KeyCustody`.
    fn test_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Builds a violation record and signs it with `key`.
    fn signed_violation(
        key: &SigningKey,
        violation: CustodyViolationType,
    ) -> ScpCustodyViolationAttestation {
        let mut att = ScpCustodyViolationAttestation {
            subject_did: test_did("subject"),
            timestamp: 1_700_000_000,
            violation,
            verifier_signature: vec![0u8; 64],
            verifier_did: test_did("verifier"),
        };
        att.verifier_signature = key.sign(&att.signing_hash().unwrap()).to_bytes().to_vec();
        att
    }

    /// Builds a counter-attestation against [`sample_violation`] and signs it
    /// with `key`.
    fn signed_counter(key: &SigningKey) -> CounterAttestation {
        let mut counter = CounterAttestation::referencing(
            &sample_violation("subject"),
            "agent key was compromised and rotated".to_string(),
            1_700_001_000,
            vec![0u8; 64],
        )
        .unwrap();
        counter.signature = key
            .sign(&counter.signing_hash().unwrap())
            .to_bytes()
            .to_vec();
        counter
    }

    #[test]
    fn violation_signature_roundtrip_category_a() {
        let key = test_signing_key(7);
        let att = signed_violation(&key, sample_category_a_violation());
        att.verify_verifier_signature(key.verifying_key().as_bytes())
            .expect("a freshly signed record verifies against its own signer");
    }

    #[test]
    fn violation_signature_roundtrip_attestation_mismatch() {
        let key = test_signing_key(9);
        let att = signed_violation(&key, sample_attestation_mismatch());
        att.verify_verifier_signature(key.verifying_key().as_bytes())
            .expect("a freshly signed record verifies against its own signer");
    }

    #[test]
    fn violation_signature_rejects_wrong_key() {
        let signer = test_signing_key(7);
        let other = test_signing_key(8);
        let att = signed_violation(&signer, sample_category_a_violation());

        let err = att
            .verify_verifier_signature(other.verifying_key().as_bytes())
            .unwrap_err();
        assert!(matches!(
            err,
            CustodyViolationError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn violation_signature_rejects_malformed_key_length() {
        let signer = test_signing_key(7);
        let att = signed_violation(&signer, sample_category_a_violation());

        let err = att.verify_verifier_signature(&[0u8; 31]).unwrap_err();
        assert!(matches!(
            err,
            CustodyViolationError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn violation_signature_rejects_tampered_subject_did() {
        let key = test_signing_key(7);
        let mut att = signed_violation(&key, sample_category_a_violation());
        att.subject_did = test_did("mallory");

        assert!(
            att.verify_verifier_signature(key.verifying_key().as_bytes())
                .is_err(),
            "retargeting a signed violation at a different subject must reject"
        );
    }

    #[test]
    fn violation_signature_rejects_tampered_timestamp() {
        let key = test_signing_key(7);
        let mut att = signed_violation(&key, sample_category_a_violation());
        att.timestamp += 1;

        assert!(
            att.verify_verifier_signature(key.verifying_key().as_bytes())
                .is_err(),
            "moving the detection timestamp must reject"
        );
    }

    #[test]
    fn violation_signature_rejects_tampered_violation_payload() {
        let key = test_signing_key(7);
        let mut att = signed_violation(&key, sample_category_a_violation());
        att.violation = CustodyViolationType::CategoryAViolation {
            action: "pre_rotation_commitment".to_string(),
            signer_key_id: SigningKeyId::Agent,
            signature_evidence: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        assert!(
            att.verify_verifier_signature(key.verifying_key().as_bytes())
                .is_err(),
            "rewriting which action was attempted must reject"
        );
    }

    #[test]
    fn violation_signature_rejects_tampered_evidence_bytes() {
        let key = test_signing_key(7);
        let mut att = signed_violation(&key, sample_category_a_violation());
        att.violation = CustodyViolationType::CategoryAViolation {
            action: "did_document_update".to_string(),
            signer_key_id: SigningKeyId::Agent,
            signature_evidence: vec![0x00, 0x00, 0x00, 0x00],
        };

        assert!(
            att.verify_verifier_signature(key.verifying_key().as_bytes())
                .is_err(),
            "swapping the cryptographic evidence must reject"
        );
    }

    #[test]
    fn violation_signature_rejects_tampered_verifier_did() {
        let key = test_signing_key(7);
        let mut att = signed_violation(&key, sample_category_a_violation());
        att.verifier_did = test_did("impostor");

        assert!(
            att.verify_verifier_signature(key.verifying_key().as_bytes())
                .is_err(),
            "reattributing a signed violation to a different verifier must reject"
        );
    }

    /// The one-byte variant discriminator at preimage position 3 separates the
    /// two variants: two records whose three payload fields carry identical
    /// bytes still hash differently.
    #[test]
    fn violation_variants_with_identical_payload_bytes_hash_differently() {
        let category_a = ScpCustodyViolationAttestation {
            subject_did: test_did("subject"),
            timestamp: 1_700_000_000,
            violation: CustodyViolationType::CategoryAViolation {
                action: "shared".to_string(),
                signer_key_id: SigningKeyId::Agent,
                signature_evidence: b"shared".to_vec(),
            },
            verifier_signature: vec![0u8; 64],
            verifier_did: test_did("verifier"),
        };
        let mismatch = ScpCustodyViolationAttestation {
            violation: CustodyViolationType::AttestationMismatch {
                claimed_custody: "shared".to_string(),
                observed_behavior: "#agent".to_string(),
                attestation_evidence: b"shared".to_vec(),
            },
            ..category_a.clone()
        };

        assert_ne!(
            category_a.signing_hash().unwrap(),
            mismatch.signing_hash().unwrap()
        );
    }

    #[test]
    fn counter_signature_roundtrip() {
        let key = test_signing_key(11);
        let counter = signed_counter(&key);
        counter
            .verify_signature(key.verifying_key().as_bytes())
            .expect("a freshly signed counter-attestation verifies against its own signer");
    }

    #[test]
    fn counter_signature_rejects_wrong_key() {
        let signer = test_signing_key(11);
        let other = test_signing_key(12);
        let counter = signed_counter(&signer);

        let err = counter
            .verify_signature(other.verifying_key().as_bytes())
            .unwrap_err();
        assert!(matches!(
            err,
            CustodyViolationError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn counter_signature_rejects_tampered_subject_did() {
        let key = test_signing_key(11);
        let mut counter = signed_counter(&key);
        counter.subject_did = test_did("mallory");

        assert!(
            counter
                .verify_signature(key.verifying_key().as_bytes())
                .is_err(),
            "reassigning a signed counter-claim to a different subject must reject"
        );
    }

    #[test]
    fn counter_signature_rejects_tampered_violation_reference() {
        let key = test_signing_key(11);
        let mut counter = signed_counter(&key);
        counter.violation_reference = [0xAB; 32];

        assert!(
            counter
                .verify_signature(key.verifying_key().as_bytes())
                .is_err(),
            "retargeting a signed counter-claim at a different violation must reject"
        );
    }

    #[test]
    fn counter_signature_rejects_tampered_explanation() {
        let key = test_signing_key(11);
        let mut counter = signed_counter(&key);
        counter.explanation = "the violation never happened".to_string();

        assert!(
            counter
                .verify_signature(key.verifying_key().as_bytes())
                .is_err(),
            "rewriting the counter-claim text must reject"
        );
    }

    #[test]
    fn counter_signature_rejects_tampered_timestamp() {
        let key = test_signing_key(11);
        let mut counter = signed_counter(&key);
        counter.timestamp -= 5_000;

        assert!(
            counter
                .verify_signature(key.verifying_key().as_bytes())
                .is_err(),
            "backdating a signed counter-claim must reject"
        );
    }

    // -------------------------------------------------------------------
    // Domain-separator pinning
    // -------------------------------------------------------------------

    /// Pins both separator byte strings. Renaming either constant changes the
    /// preimage of every record signed under it, which invalidates every
    /// signature taken before the rename; this test makes that a build failure
    /// rather than a silent break.
    #[test]
    fn domain_separators_are_pinned() {
        assert_eq!(CUSTODY_VIOLATION_DOMAIN, "SCP-CUSTODY-VIOLATION-V1:");
        assert_eq!(COUNTER_ATTESTATION_DOMAIN, "SCP-COUNTER-ATTESTATION-V1:");
    }

    // -------------------------------------------------------------------
    // §25.25 cross-implementation vectors (Vector 38, Vector 39)
    //
    // `.docs/specs/25-test-vectors.md` §25.25 states both vectors. Each test
    // below rebuilds the preimage from the literal separator bytes and the
    // §9.5.2 field encoding, independently of
    // `crate::crypto::canonical::canonical_hash`, then pins the spec's hex.
    // -------------------------------------------------------------------

    /// §25.2 reference Ed25519 seed (RFC 8032 §7.1 Test Vector 1). Vector 38's
    /// verifier signs with this key.
    const VECTOR_REF_SEED: [u8; 32] =
        hex_literal_32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

    /// §25.2 secondary Ed25519 seed (RFC 8032 §7.1 Test Vector 2). Vector 39's
    /// subject signs with this key, which §25.9 Vector 20 also assigns to
    /// `#active`.
    const VECTOR_SECONDARY_SEED: [u8; 32] =
        hex_literal_32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");

    /// §25.2 tertiary Ed25519 seed (RFC 8032 §7.1 Test Vector 3). Vector 38's
    /// `signature_evidence` comes from this key, which §25.9 Vector 20 also
    /// assigns to `#agent`.
    const VECTOR_TERTIARY_SEED: [u8; 32] =
        hex_literal_32("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");

    /// Decodes a 64-character hex string into 32 bytes at compile time, so a
    /// seed constant carries no runtime fallible conversion.
    const fn hex_literal_32(s: &str) -> [u8; 32] {
        let bytes = s.as_bytes();
        assert!(bytes.len() == 64, "expected 64 hex characters");
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = hex_nibble(bytes[i * 2]) << 4 | hex_nibble(bytes[i * 2 + 1]);
            i += 1;
        }
        out
    }

    /// Decodes one lowercase hex digit.
    const fn hex_nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("expected a lowercase hex digit"),
        }
    }

    /// Rebuilds §25.25 Vector 38: the violation record its verifier signs.
    fn vector_38() -> ScpCustodyViolationAttestation {
        let agent_key = SigningKey::from_bytes(&VECTOR_TERTIARY_SEED);
        let verifier_key = SigningKey::from_bytes(&VECTOR_REF_SEED);

        let mut record = ScpCustodyViolationAttestation {
            subject_did: DID("did:dht:z6MkCustodySubject".to_string()),
            timestamp: 1_700_000_000,
            violation: CustodyViolationType::CategoryAViolation {
                action: "did_document_update".to_string(),
                signer_key_id: SigningKeyId::Agent,
                signature_evidence: agent_key.sign(b"did_document_update").to_bytes().to_vec(),
            },
            verifier_signature: vec![0u8; 64],
            verifier_did: DID("did:dht:z6MkCustodyVerifier".to_string()),
        };
        record.verifier_signature = verifier_key
            .sign(&record.signing_hash().unwrap())
            .to_bytes()
            .to_vec();
        record
    }

    /// Rebuilds §25.25 Vector 39: the counter-attestation Vector 38's subject
    /// signs against Vector 38.
    fn vector_39() -> CounterAttestation {
        let subject_key = SigningKey::from_bytes(&VECTOR_SECONDARY_SEED);
        let mut counter = CounterAttestation::referencing(
            &vector_38(),
            "agent key compromised; rotated and republished".to_string(),
            1_700_003_600,
            vec![0u8; 64],
        )
        .unwrap();
        counter.signature = subject_key
            .sign(&counter.signing_hash().unwrap())
            .to_bytes()
            .to_vec();
        counter
    }

    /// The Vector 38 `signature_evidence` bytes the spec prints.
    #[test]
    fn vector_38_evidence_matches_spec() {
        let evidence = SigningKey::from_bytes(&VECTOR_TERTIARY_SEED)
            .sign(b"did_document_update")
            .to_bytes();
        assert_eq!(
            hex::encode(evidence),
            "c901da4cd2687a2115f83025f7a9e0db28269558848e88cf98c8714e8f50eaaf\
             7c6f1c757d5a26b471a67b58d5f32d081e6de274031b0d128165c77fe8d9f60b"
        );
    }

    /// Rebuilds the Vector 38 preimage byte-for-byte and pins its SHA-256.
    #[test]
    fn vector_38_signing_hash_matches_spec() {
        let record = vector_38();
        let evidence = SigningKey::from_bytes(&VECTOR_TERTIARY_SEED)
            .sign(b"did_document_update")
            .to_bytes();

        let mut preimage: Vec<u8> = Vec::new();
        preimage.extend_from_slice(b"SCP-CUSTODY-VIOLATION-V1:");
        preimage.extend_from_slice(&26u32.to_be_bytes()); // len("did:dht:z6MkCustodySubject")
        preimage.extend_from_slice(b"did:dht:z6MkCustodySubject");
        preimage.extend_from_slice(&1_700_000_000u64.to_be_bytes());
        preimage.push(0x00); // CategoryAViolation discriminator
        preimage.extend_from_slice(&19u32.to_be_bytes()); // len("did_document_update")
        preimage.extend_from_slice(b"did_document_update");
        preimage.extend_from_slice(&6u32.to_be_bytes()); // len("#agent")
        preimage.extend_from_slice(b"#agent");
        preimage.extend_from_slice(&64u32.to_be_bytes()); // len(signature_evidence)
        preimage.extend_from_slice(&evidence);
        preimage.extend_from_slice(&27u32.to_be_bytes()); // len("did:dht:z6MkCustodyVerifier")
        preimage.extend_from_slice(b"did:dht:z6MkCustodyVerifier");

        assert_eq!(
            preimage.len(),
            196,
            "§25.25 Vector 38 preimage is 196 bytes"
        );
        assert_eq!(
            hex::encode(&preimage),
            "5343502d435553544f44592d56494f4c4154494f4e2d56313a\
             0000001a6469643a6468743a7a364d6b437573746f64795375626a656374\
             000000006553f100\
             00\
             000000136469645f646f63756d656e745f757064617465\
             00000006236167656e74\
             00000040\
             c901da4cd2687a2115f83025f7a9e0db28269558848e88cf98c8714e8f50eaaf\
             7c6f1c757d5a26b471a67b58d5f32d081e6de274031b0d128165c77fe8d9f60b\
             0000001b6469643a6468743a7a364d6b437573746f64795665726966696572"
        );

        let expected: [u8; 32] = Sha256::digest(&preimage).into();
        assert_eq!(record.signing_hash().unwrap(), expected);
        assert_eq!(
            hex::encode(expected),
            "f71802b4a211df2a354484e410e0a16ce4865b9fdbeed4e6a6eaaf930838725a"
        );
    }

    /// Pins the Vector 38 Ed25519 signature and checks it verifies under the
    /// §25.2 reference key.
    #[test]
    fn vector_38_signature_matches_spec() {
        let record = vector_38();
        assert_eq!(
            hex::encode(&record.verifier_signature),
            "47feb109689697fe4a515e5e1b31e4ced02940e9a32d6ac2d4dbc5fec6294b59\
             7580dedfe98a0ffefb78123c3df81c6c6a1a8ebe0a22bcdc84f2910ce871560b"
        );
        let verifier_key = SigningKey::from_bytes(&VECTOR_REF_SEED);
        VerifiedCustodyViolation::verify(record, verifier_key.verifying_key().as_bytes())
            .expect("§25.25 Vector 38 verifies under the §25.2 reference key");
    }

    /// Rebuilds the Vector 39 preimage byte-for-byte and pins its SHA-256. Field
    /// 2 is the Vector 38 canonical hash, written as 32 raw bytes with no length
    /// prefix.
    #[test]
    fn vector_39_signing_hash_matches_spec() {
        let counter = vector_39();
        let reference = vector_38().signing_hash().unwrap();

        let mut preimage: Vec<u8> = Vec::new();
        preimage.extend_from_slice(b"SCP-COUNTER-ATTESTATION-V1:");
        preimage.extend_from_slice(&26u32.to_be_bytes()); // len("did:dht:z6MkCustodySubject")
        preimage.extend_from_slice(b"did:dht:z6MkCustodySubject");
        preimage.extend_from_slice(&reference); // 32 bytes, no length prefix
        preimage.extend_from_slice(&46u32.to_be_bytes()); // len(explanation)
        preimage.extend_from_slice(b"agent key compromised; rotated and republished");
        preimage.extend_from_slice(&1_700_003_600u64.to_be_bytes());

        assert_eq!(
            preimage.len(),
            147,
            "§25.25 Vector 39 preimage is 147 bytes"
        );
        assert_eq!(
            hex::encode(&preimage),
            "5343502d434f554e5445522d4154544553544154494f4e2d56313a\
             0000001a6469643a6468743a7a364d6b437573746f64795375626a656374\
             f71802b4a211df2a354484e410e0a16ce4865b9fdbeed4e6a6eaaf930838725a\
             0000002e6167656e74206b657920636f6d70726f6d697365643b20726f746174656420616e642072657075626c6973686564\
             000000006553ff10"
        );

        let expected: [u8; 32] = Sha256::digest(&preimage).into();
        assert_eq!(counter.signing_hash().unwrap(), expected);
        assert_eq!(
            hex::encode(expected),
            "7e12cde18598a11b6c270d756029e437d546c2231731f2b2add6ef41c1eb5af1"
        );
    }

    /// Pins the Vector 39 Ed25519 signature, checks it verifies under the §25.2
    /// secondary key, and checks that the same signature fails under the
    /// tertiary key — which is how §9.5.2 enforces ADR-039 acceptance criterion
    /// 18 without a `signing_key_id` field inside the signed record.
    #[test]
    fn vector_39_signature_matches_spec_and_rejects_the_agent_key() {
        let counter = vector_39();
        assert_eq!(
            hex::encode(&counter.signature),
            "c58f24edf7ffbea6cdf5a5bace97c4a49ca45a0f6338e0a75699b30c0d119176\
             2e07358be3084195f94365dc539b3047802b5ef27778a4807b13050474d31500"
        );

        let agent_key = SigningKey::from_bytes(&VECTOR_TERTIARY_SEED);
        assert!(
            VerifiedCounterAttestation::verify(
                counter.clone(),
                agent_key.verifying_key().as_bytes()
            )
            .is_err(),
            "a counter-claim signed by #active must not verify under #agent"
        );

        let subject_key = SigningKey::from_bytes(&VECTOR_SECONDARY_SEED);
        let verified =
            VerifiedCounterAttestation::verify(counter, subject_key.verifying_key().as_bytes())
                .expect("§25.25 Vector 39 verifies under the §25.2 secondary key");

        let verifier_key = SigningKey::from_bytes(&VECTOR_REF_SEED);
        let violation =
            VerifiedCustodyViolation::verify(vector_38(), verifier_key.verifying_key().as_bytes())
                .unwrap();
        verified
            .answers(&violation)
            .expect("§25.25 Vector 39 answers §25.25 Vector 38");
    }

    /// A signature taken over one record type's preimage does not verify over
    /// the other type's, because the two separators differ.
    #[test]
    fn cross_type_signature_does_not_transfer() {
        let key = test_signing_key(13);
        let counter = signed_counter(&key);

        // Reuse the counter-attestation's signature as a violation record's
        // verifier signature over an identically-valued field set.
        let att = ScpCustodyViolationAttestation {
            subject_did: counter.subject_did,
            timestamp: counter.timestamp,
            violation: sample_category_a_violation(),
            verifier_signature: counter.signature,
            verifier_did: test_did("verifier"),
        };

        assert!(
            att.verify_verifier_signature(key.verifying_key().as_bytes())
                .is_err(),
            "a counter-attestation signature must not verify as a violation signature"
        );
    }

    // -------------------------------------------------------------------
    // enforce_category_a evidence carry-through
    // -------------------------------------------------------------------

    #[test]
    fn enforce_category_a_carries_evidence_signature() {
        let evidence = [0xAB; 64];
        let violation = enforce_category_a(
            SigningKeyId::Agent,
            ActionCategory::CategoryA,
            "did:dht:alice",
            "add verification method",
            &evidence,
        )
        .unwrap_err();

        assert_eq!(violation.signature_evidence, evidence.to_vec());
    }

    #[test]
    fn enforce_category_a_result_builds_a_conformant_violation() {
        let evidence = [0xAB; 64];
        let result = enforce_category_a(
            SigningKeyId::Agent,
            ActionCategory::CategoryA,
            "did:dht:alice",
            "add verification method",
            &evidence,
        )
        .unwrap_err();

        let violation = result.into_category_a_violation().unwrap();
        match violation {
            CustodyViolationType::CategoryAViolation {
                action,
                signer_key_id,
                signature_evidence,
            } => {
                assert_eq!(action, "add verification method");
                assert_eq!(signer_key_id, SigningKeyId::Agent);
                assert_eq!(signature_evidence, evidence.to_vec());
            }
            CustodyViolationType::AttestationMismatch { .. } => {
                panic!("enforce_category_a must produce a CategoryAViolation")
            }
        }
    }

    // -------------------------------------------------------------------
    // CategoryARejection (ADR-039 enforcement-stack layer 3)
    // -------------------------------------------------------------------

    /// A rejection carrying observed evidence builds the record layer 3 requires,
    /// and that record holds the evidence bytes rather than a placeholder.
    #[test]
    fn rejection_carries_observed_evidence_into_a_record() {
        let evidence = [0xAB; 64];
        let rejection: CategoryARejection = enforce_category_a(
            SigningKeyId::Agent,
            ActionCategory::CategoryA,
            "did:dht:alice",
            "add verification method",
            &evidence,
        )
        .unwrap_err()
        .into();

        assert_eq!(rejection.violator_did(), "did:dht:alice");
        assert!(
            rejection
                .error_message()
                .contains("Category A action rejected")
        );
        match rejection.recorded_violation() {
            Some(CustodyViolationType::CategoryAViolation {
                action,
                signer_key_id,
                signature_evidence,
            }) => {
                assert_eq!(action, "add verification method");
                assert_eq!(*signer_key_id, SigningKeyId::Agent);
                assert_eq!(signature_evidence.as_slice(), evidence.as_slice());
            }
            other => panic!("expected a recorded CategoryAViolation, got {other:?}"),
        }
    }

    /// A rejection carrying no evidence still rejects, reports why no record
    /// accompanies it, and invents no evidence.
    #[test]
    fn rejection_without_evidence_reports_why_it_recorded_nothing() {
        let rejection: CategoryARejection = enforce_category_a(
            SigningKeyId::Agent,
            ActionCategory::CategoryA,
            "did:dht:alice",
            "add verification method",
            &[],
        )
        .unwrap_err()
        .into();

        assert!(rejection.recorded_violation().is_none());
        assert!(matches!(
            rejection,
            CategoryARejection::EvidenceUnusable {
                reason: CustodyViolationError::EmptyEvidence {
                    field: "signature_evidence"
                },
                ..
            }
        ));
    }

    // -------------------------------------------------------------------
    // VerifiedCustodyViolation / VerifiedCounterAttestation
    // -------------------------------------------------------------------

    /// Verification is the only way to build a verified record, and it returns
    /// the record it checked.
    #[test]
    fn verified_violation_wraps_the_record_it_checked() {
        let key = test_signing_key(7);
        let record = signed_violation(&key, sample_category_a_violation());
        let verified =
            VerifiedCustodyViolation::verify(record.clone(), key.verifying_key().as_bytes())
                .expect("a freshly signed record verifies against its own signer");

        assert_eq!(verified.record(), &record);
        assert_eq!(
            verified.reference().unwrap(),
            record.signing_hash().unwrap()
        );
        assert_eq!(verified.into_record(), record);
    }

    /// A record whose signature came from another key produces no verified
    /// value, so no store accepts it.
    #[test]
    fn verified_violation_rejects_a_wrong_key() {
        let signer = test_signing_key(7);
        let other = test_signing_key(8);
        let record = signed_violation(&signer, sample_category_a_violation());

        let err =
            VerifiedCustodyViolation::verify(record, other.verifying_key().as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            CustodyViolationError::SignatureVerificationFailed { .. }
        ));
    }

    /// A record whose fields a party altered after signing produces no verified
    /// value.
    #[test]
    fn verified_violation_rejects_a_tampered_record() {
        let key = test_signing_key(7);
        let mut record = signed_violation(&key, sample_category_a_violation());
        record.subject_did = test_did("mallory");

        assert!(VerifiedCustodyViolation::verify(record, key.verifying_key().as_bytes()).is_err());
    }

    /// Shape validation runs before signature verification, so a malformed
    /// record reports its malformed field.
    #[test]
    fn verified_violation_rejects_an_empty_signature_before_checking_it() {
        let record = ScpCustodyViolationAttestation {
            verifier_signature: Vec::new(),
            ..sample_violation("subject")
        };
        let key = test_signing_key(7);

        assert!(matches!(
            VerifiedCustodyViolation::verify(record, key.verifying_key().as_bytes()).unwrap_err(),
            CustodyViolationError::EmptyVerifierSignature
        ));
    }

    #[test]
    fn verified_counter_wraps_the_record_it_checked() {
        let key = test_signing_key(11);
        let counter = signed_counter(&key);
        let verified =
            VerifiedCounterAttestation::verify(counter.clone(), key.verifying_key().as_bytes())
                .expect("a freshly signed counter-claim verifies against its own signer");

        assert_eq!(verified.record(), &counter);
        assert_eq!(verified.into_record(), counter);
    }

    #[test]
    fn verified_counter_rejects_a_wrong_key() {
        let signer = test_signing_key(11);
        let other = test_signing_key(12);
        let counter = signed_counter(&signer);

        assert!(
            VerifiedCounterAttestation::verify(counter, other.verifying_key().as_bytes()).is_err()
        );
    }

    // -------------------------------------------------------------------
    // violation_reference binding (spec §9.5.2 derivation rule)
    // -------------------------------------------------------------------

    /// Signs `violation` with `verifier_key` and returns the verified value.
    fn verified_violation_for(
        verifier_key: &SigningKey,
        subject: &str,
    ) -> VerifiedCustodyViolation {
        let mut record = sample_violation(subject);
        record.verifier_signature = verifier_key
            .sign(&record.signing_hash().unwrap())
            .to_bytes()
            .to_vec();
        VerifiedCustodyViolation::verify(record, verifier_key.verifying_key().as_bytes()).unwrap()
    }

    /// Signs a counter-claim against `violation` with `subject_key`.
    fn verified_counter_for(
        subject_key: &SigningKey,
        violation: &VerifiedCustodyViolation,
    ) -> VerifiedCounterAttestation {
        let mut counter = CounterAttestation::referencing(
            violation.record(),
            "agent key rotated".to_string(),
            1_700_001_000,
            vec![0u8; 64],
        )
        .unwrap();
        counter.signature = subject_key
            .sign(&counter.signing_hash().unwrap())
            .to_bytes()
            .to_vec();
        VerifiedCounterAttestation::verify(counter, subject_key.verifying_key().as_bytes()).unwrap()
    }

    #[test]
    fn counter_answers_the_record_it_references() {
        let verifier = test_signing_key(31);
        let subject = test_signing_key(32);
        let violation = verified_violation_for(&verifier, "subject");
        let counter = verified_counter_for(&subject, &violation);

        counter
            .answers(&violation)
            .expect("a counter-claim built from this record answers it");
    }

    /// A counter-claim built against one record does not answer a record whose
    /// recorded facts differ, because the reference covers every such fact.
    #[test]
    fn counter_does_not_answer_a_different_record() {
        let verifier = test_signing_key(31);
        let subject = test_signing_key(32);
        let first = verified_violation_for(&verifier, "subject");
        let counter = verified_counter_for(&subject, &first);

        let mut other_record = first.record().clone();
        other_record.timestamp += 1;
        other_record.verifier_signature = verifier
            .sign(&other_record.signing_hash().unwrap())
            .to_bytes()
            .to_vec();
        let other =
            VerifiedCustodyViolation::verify(other_record, verifier.verifying_key().as_bytes())
                .unwrap();

        assert!(matches!(
            counter.answers(&other).unwrap_err(),
            CustodyViolationError::ViolationReferenceMismatch { .. }
        ));
    }

    /// One subject cannot answer a record naming another subject, even when it
    /// copies that record's reference.
    #[test]
    fn counter_does_not_answer_a_record_naming_another_subject() {
        let verifier = test_signing_key(31);
        let mallory = test_signing_key(33);
        let violation = verified_violation_for(&verifier, "alice");

        let mut counter = CounterAttestation::referencing(
            violation.record(),
            "not my agent key".to_string(),
            1_700_001_000,
            vec![0u8; 64],
        )
        .unwrap();
        counter.subject_did = test_did("mallory");
        counter.signature = mallory
            .sign(&counter.signing_hash().unwrap())
            .to_bytes()
            .to_vec();
        let mallory_counter =
            VerifiedCounterAttestation::verify(counter, mallory.verifying_key().as_bytes())
                .unwrap();

        assert!(matches!(
            mallory_counter.answers(&violation).unwrap_err(),
            CustodyViolationError::SubjectMismatch { .. }
        ));
    }

    /// A verification point that observed no signature bytes cannot mint a
    /// conformant record: the conversion reports the empty evidence instead of
    /// inventing a placeholder.
    #[test]
    fn enforce_category_a_result_rejects_empty_evidence() {
        let result = enforce_category_a(
            SigningKeyId::Agent,
            ActionCategory::CategoryA,
            "did:dht:alice",
            "add verification method",
            &[],
        )
        .unwrap_err();

        let err = result.into_category_a_violation().unwrap_err();
        assert!(matches!(
            err,
            CustodyViolationError::EmptyEvidence {
                field: "signature_evidence"
            }
        ));
    }
}
