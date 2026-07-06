//! Signed `InvitationBundle` / `JoinResponse` wire types (spec §5.12.3.1, §5.12.3.2).
//!
//! The invitation bundle is the single-delivery package that enables
//! zero-roundtrip context joining: it carries the MLS Welcome, the invitee's
//! context-specific key material, the **full genesis [`ContextParams`]** the
//! joiner installs authority from, and a visibility-filtered
//! [`MetadataSnapshot`] view — all under one creator signature.
//!
//! This module is the **pure protocol layer** for that flow, mirroring the
//! §5.13.3 `0xFF02` extension precedent in
//! [`group_context_extension`](super::group_context_extension):
//!
//! - the wire structs ([`InvitationBundle`], [`InvitationKeyMaterial`],
//!   [`JoinResponse`]),
//! - the canonical **signing-hash** construction
//!   ([`InvitationBundle::invitation_bundle_signing_hash`] /
//!   [`JoinResponse::join_response_signing_hash`]),
//!   Ed25519 [`sign`](InvitationBundle::sign) /
//!   [`verify`](InvitationBundle::verify) over that hash, and
//! - the in-bundle **structural-consistency** predicate
//!   ([`InvitationBundle::verify_structural_consistency`]).
//!
//! The HPKE seal/open of the serialized bundle (§5.12.3.1 "HPKE encryption"),
//! the DID `#active` key **resolution**, the routing-id derivation, and the
//! `0xFF02` cross-check against the joined MLS group are the **runtime layer**
//! (`scp-runtime` / `scp-mls`) — this layer takes an already-resolved key and
//! never touches the network.
//!
//! # Signing preimage vs. wire encoding (spec §5.12.3.1 "Canonicalization")
//!
//! The two encodings are deliberately independent and MUST NOT be conflated:
//!
//! - **Wire / transport envelope** — the whole struct is serialized with the
//!   codebase `MessagePack` convention ([`to_wire_bytes`](InvitationBundle::to_wire_bytes),
//!   `rmp_serde::to_vec_named`). `MessagePack` has no canonical form, so it never
//!   enters the signature.
//! - **Signature preimage** — built from **per-field RFC 8785 (JCS) hashes**:
//!   each `_hash = SHA-256(JCS(field))`, computed over the individual field
//!   **value** (not the enclosing struct), so a wire-only attribute such as
//!   `#[serde(with = "serde_bytes")]` on a byte field cannot perturb the signed
//!   bytes. JCS gives byte-identical output across independent SDK
//!   implementations; SHA-256 over those bytes is reproducible everywhere.
//!
//! See spec §5.12.3.1 and `.docs/specs/05-contexts.md`.

use std::fmt;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use scp_did::DID;

use super::metadata::{Ed25519Signature, MetadataSnapshot};
use super::params::ContextParams;
use super::roles::CapabilityCeiling;
use crate::crypto::canonical::{CanonicalField, canonical_hash};

/// Domain separator for the [`InvitationBundle`] signature preimage (§5.12.3.1).
const INVITATION_BUNDLE_DOMAIN: &str = "SCP-INVITATION-BUNDLE-V1:";

/// Domain separator for the [`JoinResponse`] signature preimage (§5.12.3.2).
const JOIN_RESPONSE_DOMAIN: &str = "SCP-JOIN-RESPONSE-V1:";

// ---------------------------------------------------------------------------
// InvitationBundleError
// ---------------------------------------------------------------------------

/// Failure kinds for [`InvitationBundle`] / [`JoinResponse`] verification and
/// (de)serialization.
///
/// [`SignatureInvalid`] is fail-closed: it covers both a well-formed signature
/// that does not verify and a malformed one (wrong length / bad point), so a
/// caller can never mistake a structurally broken signature for a valid one.
///
/// [`SignatureInvalid`]: InvitationBundleError::SignatureInvalid
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvitationBundleError {
    /// The Ed25519 signature does not verify against the provided key, or the
    /// signature bytes are malformed (not exactly 64 bytes / invalid point).
    #[error("invitation signature is invalid")]
    SignatureInvalid,

    /// A `metadata_snapshot.structural` field diverges from the corresponding
    /// signed `context_params` field (spec §5.12.3.1 validation step 2). Both
    /// are inside the same creator signature, so a divergence is a signed
    /// self-contradiction — reject.
    #[error("metadata snapshot field '{field}' is inconsistent with the signed context_params")]
    StructuralInconsistency {
        /// Name of the structural field that diverged.
        field: String,
    },

    /// Canonical (JCS) serialization of a signed field failed, or the canonical
    /// hash construction rejected an over-length field. Kept distinct from the
    /// semantic failures because it signals an internal / wire-format fault, and
    /// must never be discarded with an `unwrap` (§ "No shortcuts").
    #[error("canonical serialization failed: {0}")]
    Canonicalization(String),

    /// `MessagePack` (de)serialization of the transport envelope failed.
    #[error("wire (de)serialization failed: {0}")]
    Wire(String),
}

// ---------------------------------------------------------------------------
// InvitationKeyMaterial
// ---------------------------------------------------------------------------

/// Context-specific key material handed to the invitee inside an
/// [`InvitationBundle`] (spec §5.12.3.1).
///
/// Both fields are **raw secret key material**, so this type zeroizes on drop
/// ([`ZeroizeOnDrop`]) and its [`Debug`] impl redacts the bytes — mirroring the
/// [`SenderKey`](crate::crypto::sender_keys::SenderKey) handling. The bytes are
/// exposed to the wire only through the enclosing bundle's HPKE-encrypted
/// envelope (runtime layer); they are never logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct InvitationKeyMaterial {
    /// Symmetric key for metadata routing-ID derivation (§9.10.4.B).
    pub context_metadata_key: [u8; 32],
    /// Initial sender-key seed material (Broadcast contexts only; `None`
    /// otherwise).
    pub sender_key_seed: Option<Vec<u8>>,
}

impl fmt::Debug for InvitationKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InvitationKeyMaterial")
            .field("context_metadata_key", &"<redacted>")
            .field(
                "sender_key_seed",
                &self.sender_key_seed.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// InvitationBundle
// ---------------------------------------------------------------------------

/// The single-delivery package that enables zero-roundtrip context joining
/// (spec §5.12.3.1).
///
/// `context_params` is the **authenticated authority source** the joiner
/// enforces from; `metadata_snapshot` is a lossy display / auto-accept VIEW
/// whose structural fields MUST agree with `context_params` (checked by
/// [`Self::verify_structural_consistency`]). The creator signs a hash that
/// binds every field (see [`Self::invitation_bundle_signing_hash`]).
///
/// `Debug` is derived: `key_material` self-redacts, `welcome_message` /
/// `signature` are transport ciphertext / a public signature, so no raw secret
/// is printed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvitationBundle {
    /// The context being invited to.
    pub context_id: String,
    /// The DID of the context creator / inviter.
    pub creator_did: DID,
    /// Relay endpoints where the context is hosted.
    pub relay_urls: Vec<String>,
    /// MLS Welcome message (RFC 9420 §12.4.3.1). Empty for Broadcast contexts.
    #[serde(with = "serde_bytes")]
    pub welcome_message: Vec<u8>,
    /// Context-specific key material for the invitee.
    pub key_material: InvitationKeyMaterial,
    /// The **full genesis** [`ContextParams`] the joiner installs authority
    /// from — the authenticated authority source.
    pub context_params: ContextParams,
    /// Visibility-filtered VIEW for auto-accept policy evaluation and display.
    /// Its structural fields MUST agree with `context_params`.
    pub metadata_snapshot: MetadataSnapshot,
    /// Creator's Ed25519 signature over [`Self::invitation_bundle_signing_hash`],
    /// produced with the creator's Active Signing Key (`#active`).
    #[serde(with = "serde_bytes")]
    pub signature: Ed25519Signature,
}

impl InvitationBundle {
    /// Computes the §5.12.3.1 signature preimage hash:
    ///
    /// ```text
    /// SHA-256(
    ///   "SCP-INVITATION-BUNDLE-V1:"
    ///   || len(context_id) || context_id          // §9.5.1 length-prefixed
    ///   || len(creator_did) || creator_did         // §9.5.1 length-prefixed
    ///   || relay_urls_hash                          // SHA-256(JCS(relay_urls))
    ///   || welcome_message_hash                     // SHA-256(JCS(welcome_message))
    ///   || key_material_hash                        // SHA-256(JCS(key_material))
    ///   || genesis_params_hash                      // SHA-256(JCS(context_params))
    ///   || metadata_snapshot_hash                   // SHA-256(JCS(metadata_snapshot))
    /// )
    /// ```
    ///
    /// The domain separator is written raw (no length prefix); `context_id` /
    /// `creator_did` are length-prefixed per §9.5.1 (4-byte big-endian length +
    /// UTF-8 bytes); each `_hash` is a fixed 32-byte SHA-256 of the field's JCS
    /// encoding, inserted raw (a fixed-width value carries no length prefix,
    /// §9.5.1). `genesis_params_hash` binds the complete genesis `ContextParams`.
    ///
    /// Returns a [`Result`] because JCS serialization is fallible; the pure-hash
    /// signature the spec writes (`SHA-256(...)`) is recovered on the `Ok` path.
    /// This layer never panics on a serialization fault (§ "No shortcuts").
    ///
    /// # Errors
    ///
    /// Returns [`InvitationBundleError::Canonicalization`] if any field cannot
    /// be canonically (JCS) serialized or the canonical hash construction
    /// rejects an over-length field.
    pub fn invitation_bundle_signing_hash(&self) -> Result<[u8; 32], InvitationBundleError> {
        let relay_urls_hash = jcs_sha256(&self.relay_urls)?;
        let welcome_message_hash = jcs_sha256(&self.welcome_message)?;
        let key_material_hash = jcs_sha256(&self.key_material)?;
        let genesis_params_hash = jcs_sha256(&self.context_params)?;
        let metadata_snapshot_hash = jcs_sha256(&self.metadata_snapshot)?;

        let creator_did: &str = &self.creator_did;
        canonical_hash(
            INVITATION_BUNDLE_DOMAIN,
            &[
                CanonicalField::VarBytes(self.context_id.as_bytes()),
                CanonicalField::VarBytes(creator_did.as_bytes()),
                CanonicalField::Fixed32(&relay_urls_hash),
                CanonicalField::Fixed32(&welcome_message_hash),
                CanonicalField::Fixed32(&key_material_hash),
                CanonicalField::Fixed32(&genesis_params_hash),
                CanonicalField::Fixed32(&metadata_snapshot_hash),
            ],
        )
        .map_err(|e| InvitationBundleError::Canonicalization(e.to_string()))
    }

    /// Signs the bundle in place: computes
    /// [`Self::invitation_bundle_signing_hash`] and stores the creator's
    /// Ed25519 signature over it in [`Self::signature`].
    ///
    /// The caller supplies the already-resolved creator `#active` signing key;
    /// DID → key resolution is the runtime layer's responsibility.
    ///
    /// # Errors
    ///
    /// Returns [`InvitationBundleError::Canonicalization`] if the signing hash
    /// cannot be computed.
    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<(), InvitationBundleError> {
        let hash = self.invitation_bundle_signing_hash()?;
        self.signature = signing_key.sign(&hash).to_bytes().to_vec();
        Ok(())
    }

    /// Verifies [`Self::signature`] against `verifying_key` over
    /// [`Self::invitation_bundle_signing_hash`] using strict Ed25519
    /// verification (rejects small-order points).
    ///
    /// The caller supplies the already-resolved creator `#active` verifying key.
    ///
    /// # Errors
    ///
    /// Returns [`InvitationBundleError::SignatureInvalid`] if the signature does
    /// not verify or is malformed, or
    /// [`InvitationBundleError::Canonicalization`] if the signing hash cannot be
    /// computed.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), InvitationBundleError> {
        let hash = self.invitation_bundle_signing_hash()?;
        scp_crypto::verify_ed25519_signature(verifying_key.as_bytes(), &hash, &self.signature)
            .map_err(|_| InvitationBundleError::SignatureInvalid)
    }

    /// In-bundle **structural-consistency** check (spec §5.12.3.1 validation
    /// step 2): every field of `metadata_snapshot.structural` must agree with
    /// the corresponding field of the signed `context_params`.
    ///
    /// Both are inside the same creator signature, so a divergence is a signed
    /// self-contradiction — it lets a creator display benign structural values
    /// for the auto-accept check (§5.12.2) while enforcing hostile authority.
    /// This predicate is pure (both operands are in the bundle) and blocks that
    /// show-benign / enforce-hostile split.
    ///
    /// Set-valued fields (`ceiling`, `roles`) are compared **order-independently**
    /// (as content sets), matching the capability-ceiling semantics; scalar
    /// fields are compared for exact equality. The `0xFF02` cross-check against
    /// the joined MLS group (§5.13.3) is a separate, runtime-layer step.
    ///
    /// Note: fields that exist only in `context_params` and have no
    /// `structural` counterpart — notably `consequence_rules` /
    /// `consequence_config`, `economic_policy` detail, `tools` — cannot diverge
    /// in this VIEW and are therefore not checked here; they are authenticated
    /// solely by the bundle signature over `genesis_params_hash`.
    ///
    /// # Errors
    ///
    /// Returns [`InvitationBundleError::StructuralInconsistency`] naming the
    /// first field that diverges.
    pub fn verify_structural_consistency(&self) -> Result<(), InvitationBundleError> {
        let s = &self.metadata_snapshot.structural;
        let p = &self.context_params;

        let inconsistent = |field: &str| {
            Err(InvitationBundleError::StructuralInconsistency {
                field: field.to_owned(),
            })
        };

        if s.template_id != p.template_id {
            return inconsistent("template_id");
        }
        // Order-independent set comparison for the capability ceiling.
        if CapabilityCeiling::new(s.ceiling.iter().cloned())
            != CapabilityCeiling::new(p.ceiling.iter().cloned())
        {
            return inconsistent("ceiling");
        }
        if s.ceiling_policy != p.ceiling_policy {
            return inconsistent("ceiling_policy");
        }
        // Order-independent multiset comparison for role definitions.
        if roles_key(&s.roles) != roles_key(&p.roles) {
            return inconsistent("roles");
        }
        if s.governance != p.governance {
            return inconsistent("governance");
        }
        // `structural.ttl` is seconds; `params.ttl` is a `Duration`.
        if s.ttl != p.ttl.map(|d| d.as_secs()) {
            return inconsistent("ttl");
        }
        if s.promotion_policy != p.promotion_policy {
            return inconsistent("promotion_policy");
        }
        if s.memory_scope != p.memory_scope {
            return inconsistent("memory_scope");
        }
        if s.mode != p.mode {
            return inconsistent("mode");
        }
        if s.visibility_policy != p.metadata_visibility {
            return inconsistent("visibility_policy");
        }
        Ok(())
    }

    /// Serializes the bundle to its `MessagePack` transport envelope
    /// (`rmp_serde::to_vec_named`, spec §17.5). This is the wire form the
    /// runtime layer HPKE-encrypts; it never enters the signature.
    ///
    /// # Errors
    ///
    /// Returns [`InvitationBundleError::Wire`] on serialization failure.
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, InvitationBundleError> {
        rmp_serde::to_vec_named(self).map_err(|e| InvitationBundleError::Wire(e.to_string()))
    }

    /// Deserializes a bundle from its `MessagePack` transport envelope.
    ///
    /// # Errors
    ///
    /// Returns [`InvitationBundleError::Wire`] if the bytes are not a valid
    /// `MessagePack` encoding of an [`InvitationBundle`].
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, InvitationBundleError> {
        rmp_serde::from_slice(bytes).map_err(|e| InvitationBundleError::Wire(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// JoinResponse
// ---------------------------------------------------------------------------

/// The invitee's signed reply confirming a join (spec §5.12.3.2).
///
/// `mls_commit` / `sender_key` are transport payloads (the sender key is
/// encrypted to the context's sender-key distribution mechanism per §5.12.3.2),
/// so `Debug` is derived without redaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinResponse {
    /// The context being joined.
    pub context_id: String,
    /// The DID of the joining member.
    pub joiner_did: DID,
    /// MLS Commit confirming group join (Encrypted contexts only; empty for
    /// Broadcast).
    #[serde(with = "serde_bytes")]
    pub mls_commit: Vec<u8>,
    /// The joiner's initial sender key for this context (§9.16), encrypted to
    /// the context's current sender-key distribution mechanism.
    #[serde(with = "serde_bytes")]
    pub sender_key: Vec<u8>,
    /// Unix timestamp (seconds) of the join.
    pub timestamp: u64,
    /// Joiner's Ed25519 signature over [`Self::join_response_signing_hash`],
    /// produced with the joiner's `#active` key.
    #[serde(with = "serde_bytes")]
    pub signature: Ed25519Signature,
}

impl JoinResponse {
    /// Computes the §5.12.3.2 signature preimage hash:
    ///
    /// ```text
    /// SHA-256(
    ///   "SCP-JOIN-RESPONSE-V1:"
    ///   || len(context_id) || context_id     // §9.5.1 length-prefixed
    ///   || len(joiner_did) || joiner_did      // §9.5.1 length-prefixed
    ///   || mls_commit_hash                    // SHA-256(JCS(mls_commit))
    ///   || sender_key_hash                    // SHA-256(JCS(sender_key))
    ///   || timestamp                          // 8-byte big-endian (§9.5.1)
    /// )
    /// ```
    ///
    /// The per-field JCS hashing and length-prefix rules mirror
    /// [`InvitationBundle::invitation_bundle_signing_hash`]; `timestamp` is
    /// encoded as a fixed 8-byte big-endian `u64` per §9.5.1.
    ///
    /// # Errors
    ///
    /// Returns [`InvitationBundleError::Canonicalization`] if a field cannot be
    /// canonically (JCS) serialized or the hash construction rejects an
    /// over-length field.
    pub fn join_response_signing_hash(&self) -> Result<[u8; 32], InvitationBundleError> {
        let mls_commit_hash = jcs_sha256(&self.mls_commit)?;
        let sender_key_hash = jcs_sha256(&self.sender_key)?;

        let joiner_did: &str = &self.joiner_did;
        canonical_hash(
            JOIN_RESPONSE_DOMAIN,
            &[
                CanonicalField::VarBytes(self.context_id.as_bytes()),
                CanonicalField::VarBytes(joiner_did.as_bytes()),
                CanonicalField::Fixed32(&mls_commit_hash),
                CanonicalField::Fixed32(&sender_key_hash),
                CanonicalField::U64(self.timestamp),
            ],
        )
        .map_err(|e| InvitationBundleError::Canonicalization(e.to_string()))
    }

    /// Signs the response in place over [`Self::join_response_signing_hash`].
    ///
    /// # Errors
    ///
    /// Returns [`InvitationBundleError::Canonicalization`] if the signing hash
    /// cannot be computed.
    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<(), InvitationBundleError> {
        let hash = self.join_response_signing_hash()?;
        self.signature = signing_key.sign(&hash).to_bytes().to_vec();
        Ok(())
    }

    /// Verifies [`Self::signature`] against `verifying_key` over
    /// [`Self::join_response_signing_hash`] using strict Ed25519 verification.
    ///
    /// # Errors
    ///
    /// Returns [`InvitationBundleError::SignatureInvalid`] if the signature does
    /// not verify or is malformed, or
    /// [`InvitationBundleError::Canonicalization`] if the signing hash cannot be
    /// computed.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), InvitationBundleError> {
        let hash = self.join_response_signing_hash()?;
        scp_crypto::verify_ed25519_signature(verifying_key.as_bytes(), &hash, &self.signature)
            .map_err(|_| InvitationBundleError::SignatureInvalid)
    }

    /// Serializes the response to its `MessagePack` transport envelope.
    ///
    /// # Errors
    ///
    /// Returns [`InvitationBundleError::Wire`] on serialization failure.
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, InvitationBundleError> {
        rmp_serde::to_vec_named(self).map_err(|e| InvitationBundleError::Wire(e.to_string()))
    }

    /// Deserializes a response from its `MessagePack` transport envelope.
    ///
    /// # Errors
    ///
    /// Returns [`InvitationBundleError::Wire`] if the bytes are not a valid
    /// `MessagePack` encoding of a [`JoinResponse`].
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, InvitationBundleError> {
        rmp_serde::from_slice(bytes).map_err(|e| InvitationBundleError::Wire(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Computes `SHA-256(RFC-8785-JCS(value))` — the per-field hash used in the
/// signature preimage. Mirrors the §5.13.3 `0xFF02` extension's `jcs_sha256`.
fn jcs_sha256<T: Serialize>(value: &T) -> Result<[u8; 32], InvitationBundleError> {
    let bytes = crate::jcs::to_vec(value).map_err(InvitationBundleError::Canonicalization)?;
    Ok(Sha256::digest(&bytes).into())
}

/// Builds an order-independent key for a list of role definitions: the set of
/// `(role_name, sorted-capability-name-set)` pairs. Two role lists that differ
/// only in ordering (of roles or of capabilities within a role) produce equal
/// keys, so reordering is not treated as a structural divergence.
fn roles_key(
    roles: &[super::roles::RoleDefinition],
) -> std::collections::BTreeSet<(String, Vec<String>)> {
    roles
        .iter()
        .map(|r| {
            let mut caps: Vec<String> = r
                .capabilities
                .iter()
                .map(|c| c.name().into_owned())
                .collect();
            caps.sort();
            (r.name.clone(), caps)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::time::Duration;

    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::context::metadata::{OperationalMetadata, StructuralMetadata};
    use crate::context::params::{
        CeilingPolicy, ContextMode, GovernanceModel, MemoryScope, MetadataVisibilityPolicy,
        PromotionPolicy, TemplateId,
    };
    use crate::context::roles::Capability;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Deterministic genesis params for the fixtures.
    fn fixture_params() -> ContextParams {
        ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            ceiling_policy: CeilingPolicy::Immutable,
            promotion_policy: PromotionPolicy::NoPromotion,
            roles: Vec::new(),
            ttl: Some(Duration::from_mins(5)),
            memory_scope: MemoryScope::Ephemeral,
            governance: GovernanceModel::SingleAdmin,
            template_id: Some(TemplateId::BilateralEphemeral),
            ..ContextParams::default()
        }
    }

    /// Structural view that agrees with [`fixture_params`].
    fn fixture_structural() -> StructuralMetadata {
        StructuralMetadata {
            template_id: Some(TemplateId::BilateralEphemeral),
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            ceiling_policy: CeilingPolicy::Immutable,
            roles: Vec::new(),
            governance: GovernanceModel::SingleAdmin,
            ttl: Some(300),
            promotion_policy: PromotionPolicy::NoPromotion,
            memory_scope: MemoryScope::Ephemeral,
            mode: ContextMode::Encrypted,
            visibility_policy: MetadataVisibilityPolicy::default(),
        }
    }

    fn fixture_snapshot() -> MetadataSnapshot {
        MetadataSnapshot {
            structural: fixture_structural(),
            operational: OperationalMetadata {
                member_count: Some(1),
                context_age_secs: Some(0),
                creator_did: Some(DID::from("did:dht:z6MkCreator")),
                name: Some("invite".to_owned()),
                ..OperationalMetadata::default()
            },
        }
    }

    fn fixture_bundle() -> InvitationBundle {
        InvitationBundle {
            context_id: "ctx:invite".to_owned(),
            creator_did: DID::from("did:dht:z6MkCreator"),
            relay_urls: vec![
                "wss://relay.example/1".to_owned(),
                "wss://relay.example/2".to_owned(),
            ],
            welcome_message: b"welcome-message".to_vec(),
            key_material: InvitationKeyMaterial {
                context_metadata_key: [7u8; 32],
                sender_key_seed: Some(vec![9, 9, 9, 9]),
            },
            context_params: fixture_params(),
            metadata_snapshot: fixture_snapshot(),
            signature: vec![0u8; 64],
        }
    }

    fn fixture_join() -> JoinResponse {
        JoinResponse {
            context_id: "ctx:invite".to_owned(),
            joiner_did: DID::from("did:dht:z6MkJoiner"),
            mls_commit: b"mls-commit".to_vec(),
            sender_key: b"sender-key-ciphertext".to_vec(),
            timestamp: 1_700_000_000,
            signature: vec![0u8; 64],
        }
    }

    // -- KAT: pinned signing-hash digests (cross-implementation anchor) --------

    #[test]
    fn kat_invitation_bundle_signing_hash() {
        let bundle = fixture_bundle();
        let hash = bundle.invitation_bundle_signing_hash().unwrap();
        // Regenerated when `ContextParams` gained the `capability_requirements`
        // field (SCP-ACR-008, spec §7.3.4.4 / ADR-041 AC6). The bundle signs the
        // full genesis `ContextParams` via `genesis_params_hash`, so the
        // additional (default-empty) field is folded into the JCS canonical form
        // and thus into this digest — an intended encoding change, not a
        // regression.
        assert_eq!(
            hex::encode(hash),
            "222a69e8987a1619f0eee9d2c6c830bda19f5f675b7650ca665b1bd3b82906af",
            "invitation bundle signing-hash KAT"
        );
    }

    #[test]
    fn kat_join_response_signing_hash() {
        let join = fixture_join();
        let hash = join.join_response_signing_hash().unwrap();
        assert_eq!(
            hex::encode(hash),
            "1fa626af9d1d94604aab196b7abfca4b057ae7742b04b9e3302a0fe2ea8cab77",
            "join response signing-hash KAT"
        );
    }

    // -- Sign / verify round trips ---------------------------------------------

    #[test]
    fn bundle_sign_verify_round_trip() {
        let sk = signing_key(1);
        let vk = sk.verifying_key();
        let mut bundle = fixture_bundle();
        bundle.sign(&sk).unwrap();
        assert_eq!(bundle.signature.len(), 64);
        assert!(bundle.verify(&vk).is_ok());
    }

    #[test]
    fn join_sign_verify_round_trip() {
        let sk = signing_key(2);
        let vk = sk.verifying_key();
        let mut join = fixture_join();
        join.sign(&sk).unwrap();
        assert!(join.verify(&vk).is_ok());
    }

    #[test]
    fn bundle_verify_rejects_tampered_signature() {
        let sk = signing_key(3);
        let vk = sk.verifying_key();
        let mut bundle = fixture_bundle();
        bundle.sign(&sk).unwrap();
        bundle.signature[0] ^= 0xFF;
        assert!(matches!(
            bundle.verify(&vk),
            Err(InvitationBundleError::SignatureInvalid)
        ));
    }

    #[test]
    fn bundle_verify_rejects_wrong_key() {
        let sk = signing_key(4);
        let mut bundle = fixture_bundle();
        bundle.sign(&sk).unwrap();
        let other_vk = signing_key(5).verifying_key();
        assert!(matches!(
            bundle.verify(&other_vk),
            Err(InvitationBundleError::SignatureInvalid)
        ));
    }

    #[test]
    fn bundle_verify_rejects_malformed_signature_length() {
        let sk = signing_key(6);
        let vk = sk.verifying_key();
        let mut bundle = fixture_bundle();
        bundle.sign(&sk).unwrap();
        bundle.signature.truncate(63);
        assert!(matches!(
            bundle.verify(&vk),
            Err(InvitationBundleError::SignatureInvalid)
        ));
    }

    #[test]
    fn bundle_verify_rejects_tampered_params() {
        // Mutating a signed field after signing must invalidate the signature.
        let sk = signing_key(7);
        let vk = sk.verifying_key();
        let mut bundle = fixture_bundle();
        bundle.sign(&sk).unwrap();
        bundle.context_params.governance = GovernanceModel::Majority {
            eligible_voters: vec![DID::from("did:dht:z6MkX")],
        };
        assert!(matches!(
            bundle.verify(&vk),
            Err(InvitationBundleError::SignatureInvalid)
        ));
    }

    #[test]
    fn signing_hash_excludes_signature_field() {
        let mut bundle = fixture_bundle();
        let before = bundle.invitation_bundle_signing_hash().unwrap();
        bundle.signature = vec![0xAB; 64];
        let after = bundle.invitation_bundle_signing_hash().unwrap();
        assert_eq!(before, after, "signature must not be part of the preimage");
    }

    // -- Structural consistency ------------------------------------------------

    #[test]
    fn structural_consistency_accepts_matching() {
        assert!(fixture_bundle().verify_structural_consistency().is_ok());
    }

    #[test]
    fn structural_consistency_ceiling_order_independent() {
        let mut bundle = fixture_bundle();
        // Reverse the structural ceiling ordering; same set ⇒ still consistent.
        bundle.metadata_snapshot.structural.ceiling =
            vec![Capability::MessagesWrite, Capability::MessagesRead];
        assert!(bundle.verify_structural_consistency().is_ok());
    }

    #[test]
    fn structural_consistency_rejects_governance() {
        let mut bundle = fixture_bundle();
        bundle.metadata_snapshot.structural.governance = GovernanceModel::Unanimity {
            eligible_voters: vec![DID::from("did:dht:z6MkX")],
        };
        assert!(matches!(
            bundle.verify_structural_consistency(),
            Err(InvitationBundleError::StructuralInconsistency { field }) if field == "governance"
        ));
    }

    #[test]
    fn structural_consistency_rejects_ceiling() {
        let mut bundle = fixture_bundle();
        bundle.metadata_snapshot.structural.ceiling = vec![Capability::MessagesRead];
        assert!(matches!(
            bundle.verify_structural_consistency(),
            Err(InvitationBundleError::StructuralInconsistency { field }) if field == "ceiling"
        ));
    }

    #[test]
    fn structural_consistency_rejects_ceiling_policy() {
        let mut bundle = fixture_bundle();
        bundle.metadata_snapshot.structural.ceiling_policy = CeilingPolicy::Governed;
        assert!(matches!(
            bundle.verify_structural_consistency(),
            Err(InvitationBundleError::StructuralInconsistency { field }) if field == "ceiling_policy"
        ));
    }

    #[test]
    fn structural_consistency_rejects_mode() {
        let mut bundle = fixture_bundle();
        bundle.metadata_snapshot.structural.mode = ContextMode::Broadcast;
        assert!(matches!(
            bundle.verify_structural_consistency(),
            Err(InvitationBundleError::StructuralInconsistency { field }) if field == "mode"
        ));
    }

    #[test]
    fn structural_consistency_rejects_ttl() {
        let mut bundle = fixture_bundle();
        bundle.metadata_snapshot.structural.ttl = Some(999);
        assert!(matches!(
            bundle.verify_structural_consistency(),
            Err(InvitationBundleError::StructuralInconsistency { field }) if field == "ttl"
        ));
    }

    #[test]
    fn structural_consistency_rejects_memory_scope() {
        let mut bundle = fixture_bundle();
        bundle.metadata_snapshot.structural.memory_scope = MemoryScope::Full;
        assert!(matches!(
            bundle.verify_structural_consistency(),
            Err(InvitationBundleError::StructuralInconsistency { field }) if field == "memory_scope"
        ));
    }

    #[test]
    fn structural_consistency_rejects_template_id() {
        let mut bundle = fixture_bundle();
        bundle.metadata_snapshot.structural.template_id = Some(TemplateId::Coordination);
        assert!(matches!(
            bundle.verify_structural_consistency(),
            Err(InvitationBundleError::StructuralInconsistency { field }) if field == "template_id"
        ));
    }

    // -- Wire (MessagePack) round trips ----------------------------------------

    #[test]
    fn bundle_wire_round_trip() {
        let sk = signing_key(8);
        let mut bundle = fixture_bundle();
        bundle.sign(&sk).unwrap();
        let bytes = bundle.to_wire_bytes().unwrap();
        let decoded = InvitationBundle::from_wire_bytes(&bytes).unwrap();
        assert_eq!(decoded, bundle);
        // Decoded bundle still verifies (wire round-trip preserved the preimage).
        assert!(decoded.verify(&sk.verifying_key()).is_ok());
    }

    #[test]
    fn join_wire_round_trip() {
        let sk = signing_key(9);
        let mut join = fixture_join();
        join.sign(&sk).unwrap();
        let bytes = join.to_wire_bytes().unwrap();
        let decoded = JoinResponse::from_wire_bytes(&bytes).unwrap();
        assert_eq!(decoded, join);
        assert!(decoded.verify(&sk.verifying_key()).is_ok());
    }

    #[test]
    fn from_wire_bytes_rejects_garbage() {
        assert!(matches!(
            InvitationBundle::from_wire_bytes(b"not messagepack"),
            Err(InvitationBundleError::Wire(_))
        ));
    }

    // -- Secret hygiene --------------------------------------------------------

    #[test]
    fn key_material_debug_redacts_secrets() {
        let km = InvitationKeyMaterial {
            context_metadata_key: [0x42; 32],
            sender_key_seed: Some(vec![1, 2, 3]),
        };
        let rendered = format!("{km:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("66")); // 0x42 would render as `66` in a byte array
        assert!(!rendered.contains('1'), "raw seed bytes must not appear");
    }
}
