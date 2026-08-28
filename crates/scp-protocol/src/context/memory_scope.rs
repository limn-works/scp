//! Memory scope enforcement and key destruction data types.
//!
//! Implements ADR-018 (`.docs/adrs/phase-4.md`), sections 5-9:
//!
//! - [`KeyDestructionLevel`] -- Attestation level for key destruction
//!   verification (hardware-attested, software-only, no attestation).
//! - [`RelayDeletionRequest`] -- Request to delete encrypted event data from a
//!   relay.
//! - [`RelayDeletionTracker`] -- Tracks relay compliance with deletion requests
//!   and deprioritizes non-compliant relays.
//! - [`validate_memory_scope_for_broadcast`] -- Rejects `Ephemeral` or
//!   `Summary` memory scopes for broadcast contexts.
//!
//! Key-destruction ATTESTATION ([`KeyDestructionAttestation`]) is a pure-data
//! record defined here; it is BUILT at the actor finalize seam
//! (`scp_runtime::context::ttl_close_helpers::finalize_close`) from the observed
//! disposal outcome. The former runtime-side `KeyDestructionOrchestrator` was
//! deleted in #2199 (dead after #2148 moved crypto disposal onto the actor).
//!
//! # Key Destruction
//!
//! Key destruction makes content physically unreadable, enforced by
//! cryptography rather than policy. Destroying MLS tree secrets, epoch key
//! schedules, and application key material makes all historical content
//! physically unreadable. Relay deletion tracking deprioritizes non-compliant
//! relays but does not gate protocol operation.
//!
//! # Broadcast Restriction
//!
//! Broadcast contexts (spec section 5.14) use per-author keys without MLS
//! group management. Forward secrecy depends on MLS epoch ratcheting, which
//! broadcast mode lacks. Ephemeral/Summary scopes promise key destruction
//! semantics that broadcast mode cannot deliver. Only `MemoryScope::Full` is
//! permitted for broadcast contexts.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::{ContextError, ContextMode, MemoryScope};
use crate::crypto::canonical::{
    CanonicalError, CanonicalField, canonical_hash, canonical_hash_bytes,
};

// ---------------------------------------------------------------------------
// Type aliases (per-module pattern used throughout scp-core)
// ---------------------------------------------------------------------------

/// A context identifier string.
///
/// Represented as a plain `String`. This matches the type alias pattern used
/// across `scp-core` modules (`event_log`, `discovery`, `context`).
pub type ContextId = String;

/// An opaque blob identifier (SHA-256 hash of the blob content).
///
/// Represented as `[u8; 32]` per ADR-005 in `.docs/adrs/phase-1.md`.
pub type BlobId = [u8; 32];

// ---------------------------------------------------------------------------
// KeyDestructionLevel
// ---------------------------------------------------------------------------

/// Attestation level for key destruction verification.
///
/// The protocol records what level of assurance was achieved during key
/// destruction. This is metadata recorded in the close event -- not a gate.
/// The protocol works regardless of attestation level, but higher assurance
/// levels are visible to other participants.
///
/// See ADR-018 acceptance criterion 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyDestructionLevel {
    /// Key destruction is attested by hardware security module (Secure
    /// Enclave, Android Keystore). Provides the highest assurance that
    /// key material has been physically erased.
    HardwareAttested,
    /// Key destruction is attested by software-only mechanisms. The key
    /// material was zeroed in memory and removed from persistent storage,
    /// but without hardware-level guarantees.
    SoftwareOnly,
    /// No attestation is available. Key destruction was requested but
    /// cannot be verified. This is the lowest assurance level.
    NoAttestation,
}

impl std::fmt::Display for KeyDestructionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HardwareAttested => write!(f, "HardwareAttested"),
            Self::SoftwareOnly => write!(f, "SoftwareOnly"),
            Self::NoAttestation => write!(f, "NoAttestation"),
        }
    }
}

// ---------------------------------------------------------------------------
// RelayDeletionRequest
// ---------------------------------------------------------------------------

/// A request to delete encrypted event data from a relay.
///
/// Issued during ephemeral or summary context close. The relay is expected
/// to delete the specified blobs. Relay compliance is tracked by
/// [`RelayDeletionTracker`] -- non-compliant relays are deprioritized for
/// future context creation.
///
/// See ADR-018 acceptance criterion 5 and 8.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDeletionRequest {
    /// URL of the relay to send the deletion request to.
    pub relay_url: String,
    /// Blob identifiers to delete from the relay.
    pub blob_ids: Vec<BlobId>,
    /// Context identifier for which the blobs were stored.
    pub context_id: ContextId,
    /// Unix timestamp (seconds) when the deletion was requested.
    pub requested_at: u64,
}

// ---------------------------------------------------------------------------
// RelayDeletionResponse
// ---------------------------------------------------------------------------

/// Relay response status for a deletion request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeletionResponseStatus {
    /// The relay confirmed that all requested blobs were deleted.
    Confirmed,
    /// The relay partially deleted the requested blobs (some remain).
    Partial,
    /// The relay rejected or failed to process the deletion request.
    Failed,
    /// No response was received from the relay within the expected window.
    NoResponse,
}

// ---------------------------------------------------------------------------
// KeyDestructionAttestation (internal tracking)
// ---------------------------------------------------------------------------

/// Internal attestation of key destruction, recorded in the close event.
///
/// See ADR-018 acceptance criterion 7: verification level is metadata
/// recorded in the close event -- not a gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDestructionAttestation {
    /// Context for which keys were destroyed.
    pub context_id: ContextId,
    /// Level of attestation achieved.
    pub level: KeyDestructionLevel,
    /// Unix timestamp (seconds) when destruction was attested.
    pub attested_at: u64,
    /// Whether MLS group state (tree secrets, epoch key schedules,
    /// application key material) was destroyed.
    pub mls_group_destroyed: bool,
    /// Whether all sender keys for this context were destroyed.
    pub sender_keys_destroyed: bool,
}

// ---------------------------------------------------------------------------
// DestructionMethod (§9.15)
// ---------------------------------------------------------------------------

/// Method used for key destruction.
///
/// A value of this type reaches a consumer only as the output of
/// [`PublishableKeyDestructionAttestation::verified_method`], which applies the
/// clauses of §27.4.6 in `.docs/specs/27-attestations.md`. Those clauses state a
/// human ruling of 2026-08-25, which that section quotes: a record declaring
/// [`DestructionMethod::HardwareBacked`] reads as
/// [`DestructionMethod::SoftwareOnly`] unless a platform attestation proof
/// accompanies it and a verification of that proof returns a pass. §9.15 of the
/// security spec assigns the confidence rating over the method a consumer
/// verified, never the method a record declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DestructionMethod {
    /// Key destruction is software-only (`memset(0)` on key material in
    /// memory). Memory dumps, swap files, or crash logs may have retained
    /// the key.
    ///
    /// Declared first so that this variant's ordinal, `0`, equals the
    /// discriminator §9.5.2 of the security spec assigns it. A binding author
    /// who reaches for an ordinal, a `rawValue`, or a compact enum
    /// serialization reads the same byte the preimage carries.
    SoftwareOnly,
    /// Key destruction is backed by a hardware security module (Secure
    /// Enclave, Android Keystore). The hardware claims the key is gone.
    HardwareBacked,
}

impl DestructionMethod {
    /// The one-byte discriminator this variant contributes to the
    /// key-destruction signing preimage.
    ///
    /// §9.5.2 of the security spec assigns the encoding in its
    /// `KeyDestructionAttestation` row: `0x00` for
    /// [`DestructionMethod::SoftwareOnly`] and `0x01` for
    /// [`DestructionMethod::HardwareBacked`]. The values follow this enum's
    /// declaration order, as `InnerEnvelope.message_type` does, so an
    /// implementation that reaches for a variant ordinal reads the same byte.
    #[must_use]
    pub const fn discriminator(self) -> u8 {
        match self {
            Self::SoftwareOnly => 0x00,
            Self::HardwareBacked => 0x01,
        }
    }
}

/// Renders the variant name for a human reader.
///
/// The signing preimage does not use this output. §9.5.2 of the security spec
/// encodes `method` as the one-byte [`DestructionMethod::discriminator`], and
/// `"SCP-KEY-DESTRUCTION-V1:"` — which wrote this `Display` output behind a
/// 4-byte length prefix — no longer exists.
impl std::fmt::Display for DestructionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HardwareBacked => write!(f, "HardwareBacked"),
            Self::SoftwareOnly => write!(f, "SoftwareOnly"),
        }
    }
}

// ---------------------------------------------------------------------------
// PlatformAttestation (§9.15)
// ---------------------------------------------------------------------------

/// The DID verification-method fragment that signed a key-destruction
/// attestation.
///
/// §9.5.2 of the security spec binds this value in field 6 of the preimage, so
/// a verifier reads the intended verification method out of the signed bytes.
///
/// The two variants are the union of what the security spec's two incompatible
/// sentences admit. §9.15 permits `#0` or `#active`; §9.7.4 states that `#0` is
/// "Used ONLY for DID document updates and signing pre-rotation commitments,"
/// which excludes `#0` here. §27.4.6 of `.docs/specs/27-attestations.md`
/// records the pair as contradiction C35 and open question OQ-53. This type
/// admits everything either sentence admits, so it decides neither, and it
/// admits nothing beyond them. It also excludes `#agent`, which §9.15 excludes.
/// Open question OQ-53 records that §9.15 is the only artifact stating that
/// exclusion: ADR-039's Category A names four actions the agent key must not
/// sign and a destruction attestation is not one of them, and its
/// key-properties table gives `#agent` "Yes (within permission scope)" for
/// operational actions.
///
/// Wire-serializes as `"#0"` / `"#active"`, the values §9.15 of the security
/// spec states and field 6 of the §9.5.2 preimage carries. The `Serialize` and
/// `Deserialize` implementations route through [`DestructionSignerKeyId::as_fragment`]
/// and [`DestructionSignerKeyId::from_fragment`] rather than deriving, so the
/// wire alphabet and the preimage alphabet are the same one, as
/// `scp_did::SigningKeyId` does for `InnerEnvelope` and `KeyPackageAttestation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestructionSignerKeyId {
    /// The Identity Key, `#0`.
    Identity,
    /// The Active Signing Key, `#active`.
    Active,
}

impl DestructionSignerKeyId {
    /// The DID document fragment reference this variant names.
    ///
    /// Field 6 of the §9.5.2 preimage carries the UTF-8 bytes of this string
    /// behind a 4-byte big-endian length prefix.
    #[must_use]
    pub const fn as_fragment(self) -> &'static str {
        match self {
            Self::Identity => "#0",
            Self::Active => "#active",
        }
    }

    /// Parses a DID document fragment reference into a variant.
    ///
    /// Returns `None` for every fragment outside the permitted pair, `#agent`
    /// included. This is the single canonical string-to-enum decoder, so the
    /// permitted set stays closed in one place.
    #[must_use]
    pub fn from_fragment(fragment: &str) -> Option<Self> {
        match fragment {
            "#0" => Some(Self::Identity),
            "#active" => Some(Self::Active),
            _ => None,
        }
    }
}

impl std::fmt::Display for DestructionSignerKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_fragment())
    }
}

impl Serialize for DestructionSignerKeyId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_fragment())
    }
}

impl<'de> Deserialize<'de> for DestructionSignerKeyId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let fragment = String::deserialize(deserializer)?;
        Self::from_fragment(&fragment).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "signing_key_id must be \"#0\" or \"#active\", got {fragment:?}"
            ))
        })
    }
}

/// Domain separator for the key-destruction signing preimage.
///
/// §9.18.2 of the security spec registers it, and §9.5.2 of that spec states
/// the field order it prefixes. The `V2` suffix replaces
/// `"SCP-KEY-DESTRUCTION-V1:"`, whose preimage covered neither
/// `platform_attestation` nor `signing_key_id`, encoded `method` as a
/// length-prefixed variant name, and carried no SHA-256. §9.5.1 of the security
/// spec requires the increment: "Changing any field's encoding, adding a field,
/// or removing a field requires incrementing the version."
pub const KEY_DESTRUCTION_DOMAIN: &str = "SCP-KEY-DESTRUCTION-V2:";

/// Domain separator for the hash of a [`PlatformAttestation`] proof body.
///
/// §9.18.2 of the security spec registers it. The key-destruction preimage
/// carries the proof as this 32-byte hash, which lets an absent proof take
/// §9.5.1's `SHA-256(0x00)` sentinel at the same width. §9.5.1 states why the
/// present case hashes domain-separated bytes: "The sentinel is
/// distinguishable from any real hash because `SHA-256(0x00)` is not a valid
/// hash of structured data with a domain separator."
pub const DESTRUCTION_PROOF_DOMAIN: &str = "SCP-DESTRUCTION-PROOF-V1:";

/// Platform-provided attestation for key destruction, if available.
///
/// Contains opaque attestation data from the platform's hardware security
/// module (e.g., Secure Enclave attestation blob, Android Keystore
/// attestation certificate chain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformAttestation {
    /// Opaque platform attestation data (format is platform-specific).
    pub attestation_data: Vec<u8>,
    /// Human-readable platform identifier (e.g., "apple-secure-enclave",
    /// "android-keystore").
    pub platform: String,
}

impl PlatformAttestation {
    /// The 32-byte hash this proof contributes to the key-destruction signing
    /// preimage (§9.5.2 of the security spec, field 4).
    ///
    /// `SHA-256("SCP-DESTRUCTION-PROOF-V1:" || BE32(len(attestation_data)) ||
    /// attestation_data || BE32(len(platform)) || platform)`.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalError::FieldTooLarge`] when `attestation_data` or
    /// `platform` exceeds `u32::MAX` bytes, which no length prefix can encode.
    pub fn proof_hash(&self) -> Result<[u8; 32], CanonicalError> {
        canonical_hash(
            DESTRUCTION_PROOF_DOMAIN,
            &[
                CanonicalField::VarBytes(&self.attestation_data),
                CanonicalField::VarBytes(self.platform.as_bytes()),
            ],
        )
    }
}

// ---------------------------------------------------------------------------
// PublishableKeyDestructionAttestation (§9.15)
// ---------------------------------------------------------------------------

/// Publishable key destruction attestation per spec §9.15.
///
/// Published to relays after context key destruction. The signature remains
/// verifiable after context keys are destroyed because it is bound to an
/// identity key, not to the context key material.
///
/// Which verification method may sign is unsettled. §9.15 of the security spec
/// permits `#0` (Identity Key) or `#active` (Active Signing Key) and excludes
/// `#agent` (ADR-039); §9.7.4 of the same spec states that `#0` is "Used ONLY
/// for DID document updates and signing pre-rotation commitments," which a
/// destruction attestation is not. §27.4.6 of
/// `.docs/specs/27-attestations.md` records the pair as contradiction C35 and
/// open question OQ-53. [`Self::signing_key_id`] binds whichever fragment
/// signed, so a verifier enforces whichever rule a human settles.
///
/// Trust levels, per §9.15 of the security spec, which rates the method a
/// consumer verified and never the method this record declared:
/// - **Hardware-attested** (a verification of `platform_attestation` returned a
///   pass): High confidence (hardware claims key is gone).
/// - **Software-only**, and every record declaring `HardwareBacked` that no
///   verified proof accompanies: Moderate confidence (memory zeroed, no
///   hardware guarantee).
/// - **No attestation:** Member went offline before close (not represented
///   here — the absence of an attestation IS the "no attestation" case).
///
/// Read the method through [`Self::verified_method`], which applies clauses 1
/// through 3 of §27.4.6 in `.docs/specs/27-attestations.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishableKeyDestructionAttestation {
    /// The context for which keys were destroyed.
    pub context_id: ContextId,
    /// The DID of the member who destroyed their keys.
    pub member_did: String,
    /// Unix timestamp (seconds) when keys were destroyed.
    pub destroyed_at: u64,
    /// Platform attestation proof accompanying the declaration. `None` for
    /// software-only destruction.
    ///
    /// A declaration naming [`DestructionMethod::HardwareBacked`] carries no
    /// weight unless this proof is present and a verification of it returns a
    /// pass (§27.4.6 of `.docs/specs/27-attestations.md`, clause 1). No SCP
    /// implementation verifies this proof today, and open questions OQ-2 and
    /// OQ-29 of that spec own the verification procedure and what a pass would
    /// establish.
    ///
    /// [`Self::signing_preimage`] covers this field as
    /// [`PlatformAttestation::proof_hash`], so a holder who strips it or swaps
    /// a different proof in invalidates the signature. §9.5.2 of the security
    /// spec states the encoding, and §9.5.1's `SHA-256(0x00)` sentinel encodes
    /// the absent case.
    pub platform_attestation: Option<PlatformAttestation>,
    /// The destruction method the publisher declared.
    ///
    /// This is a declaration, not a finding. Read it through
    /// [`Self::verified_method`], which applies the §27.4.6 clauses.
    ///
    /// The field is crate-private, which closes the typed Rust read path and
    /// closes no other. The struct derives `Serialize` and `Debug`, so the
    /// declaration reaches any consumer that formats or serializes the record,
    /// and `the_declaration_still_round_trips_on_the_wire` pins that on
    /// purpose: a republished record carries the publisher's declaration
    /// unchanged. Clause 4 of §27.4.6 addresses that consumer too.
    pub(crate) method: DestructionMethod,
    /// The DID verification-method fragment that produced `signature`.
    ///
    /// §9.5.2 of the security spec places this field in the signing preimage,
    /// so a verifier reads the intended key out of the signed bytes rather than
    /// out of the transport that carried them. A verifier resolves the fragment
    /// against `member_did` above, which the same preimage binds.
    ///
    /// [`DestructionSignerKeyId`] admits the union of what §9.15 and §9.7.4 of
    /// the security spec each admit, so the type decides neither arm of
    /// contradiction C35. It also rejects `#agent`, which §9.15 excludes and
    /// which open question OQ-53 records as resting on §9.15 alone.
    pub signing_key_id: DestructionSignerKeyId,
    /// Ed25519 signature over the 32-byte [`Self::canonical_hash`] output.
    ///
    /// §9.15 of the security spec states one rule for which key signs, and
    /// §9.7.4 of the same spec states another; §27.4.6 of
    /// `.docs/specs/27-attestations.md` records the pair as contradiction C35
    /// and open question OQ-53. Whichever rule a human settles,
    /// `signing_key_id` above binds the fragment that actually signed, so a
    /// verifier can enforce it.
    ///
    /// Stored as `Vec<u8>` (always 64 bytes) because `[u8; 64]` does not
    /// implement `Serialize`/`Deserialize` in serde without additional
    /// configuration.
    pub signature: Vec<u8>,
}

impl PublishableKeyDestructionAttestation {
    /// Builds a publishable destruction attestation from a member's own
    /// destruction outcome.
    ///
    /// `method` is the declaration the publisher writes into the record. What a
    /// consumer reads back is [`Self::verified_method`], not this argument.
    #[must_use]
    pub const fn new(
        context_id: ContextId,
        member_did: String,
        destroyed_at: u64,
        platform_attestation: Option<PlatformAttestation>,
        method: DestructionMethod,
        signing_key_id: DestructionSignerKeyId,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            context_id,
            member_did,
            destroyed_at,
            platform_attestation,
            method,
            signing_key_id,
            signature,
        }
    }

    /// The destruction method a consumer reads.
    ///
    /// Applies clauses 1 through 3 of §27.4.6 in
    /// `.docs/specs/27-attestations.md` to the declared value: a record
    /// declaring [`DestructionMethod::HardwareBacked`] reads as
    /// [`DestructionMethod::SoftwareOnly`] unless a verification of the
    /// accompanying `platform_attestation` returns a pass.
    ///
    /// This function fails closed to [`DestructionMethod::SoftwareOnly`] for
    /// every declared value. No SCP implementation verifies a
    /// `platform_attestation`, and no artifact states the checks such a
    /// verification would run — open questions OQ-2 and OQ-29.
    ///
    /// [`Self::signing_preimage`] covers the proof, so a holder cannot swap the
    /// proof a signer chose for a different one. Which platform event that
    /// proof reports, and whether it reports one about this member, this
    /// context, and this key material, are the three properties §27.4.6 of
    /// `.docs/specs/27-attestations.md` derives and open question OQ-2 owns.
    /// The signed scope binds which proof a signer chose; it does not make that
    /// proof report a destruction.
    #[must_use]
    pub const fn verified_method(&self) -> DestructionMethod {
        // Both declared variants map to `SoftwareOnly` today. The match names
        // every variant rather than returning the constant, so a third variant
        // fails this crate's build until a human states what clause 1 admits
        // for it.
        match self.method {
            DestructionMethod::SoftwareOnly | DestructionMethod::HardwareBacked => {
                DestructionMethod::SoftwareOnly
            }
        }
    }

    /// Validates that the signature field is the correct length (64 bytes).
    #[must_use]
    pub const fn has_valid_signature_length(&self) -> bool {
        self.signature.len() == 64
    }

    /// The six canonical fields of the signing preimage, in the order §9.5.2 of
    /// the security spec assigns them.
    ///
    /// `proof_hash` carries [`PlatformAttestation::proof_hash`] when the record
    /// holds a proof, and `None` when it does not. The caller computes it and
    /// lends it, because [`CanonicalField::Fixed32`] borrows the array.
    fn canonical_fields<'a>(&'a self, proof_hash: Option<&'a [u8; 32]>) -> [CanonicalField<'a>; 6] {
        [
            CanonicalField::VarBytes(self.context_id.as_bytes()),
            CanonicalField::VarBytes(self.member_did.as_bytes()),
            CanonicalField::U64(self.destroyed_at),
            proof_hash.map_or(CanonicalField::Absent, CanonicalField::Fixed32),
            CanonicalField::U8(self.method.discriminator()),
            CanonicalField::VarBytes(self.signing_key_id.as_fragment().as_bytes()),
        ]
    }

    /// Hashes the accompanying proof, or returns `None` when the record carries
    /// none.
    fn proof_hash(&self) -> Result<Option<[u8; 32]>, CanonicalError> {
        self.platform_attestation
            .as_ref()
            .map(PlatformAttestation::proof_hash)
            .transpose()
    }

    /// Returns the §9.5.1 canonical preimage — the bytes the hash covers.
    ///
    /// §9.5.2 of the security spec states the field order and every encoding:
    ///
    /// ```text
    /// "SCP-KEY-DESTRUCTION-V2:"
    ///   || len(context_id) (4 bytes BE) || context_id
    ///   || len(member_did) (4 bytes BE) || member_did
    ///   || destroyed_at (8 bytes BE)
    ///   || platform_attestation (32 bytes: proof_hash, or SHA-256(0x00))
    ///   || method (1 byte: 0x00 SoftwareOnly, 0x01 HardwareBacked)
    ///   || len(signing_key_id) (4 bytes BE) || signing_key_id
    /// ```
    ///
    /// The order matches this struct's declaration order and §9.15's record
    /// listing, so a binding author transcribing either produces the same
    /// bytes.
    ///
    /// A signer signs [`Self::canonical_hash`], not these bytes. This method
    /// exists so a conformance test can compare the preimage against the
    /// known-answer vectors in §25.25 of `.docs/specs/25-test-vectors.md`.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalError::FieldTooLarge`] when a variable-length field
    /// exceeds `u32::MAX` bytes, which no length prefix can encode.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, CanonicalError> {
        let proof_hash = self.proof_hash()?;
        canonical_hash_bytes(
            KEY_DESTRUCTION_DOMAIN.as_bytes(),
            &self.canonical_fields(proof_hash.as_ref()),
        )
    }

    /// Returns the 32-byte SHA-256 hash an Ed25519 signature over this record
    /// covers.
    ///
    /// §9.5.1 of the security spec states the construction for every signed
    /// structure: `SHA-256(domain_separator || field_1 || ... || field_N)`.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalError::FieldTooLarge`] when a variable-length field
    /// exceeds `u32::MAX` bytes, which no length prefix can encode.
    pub fn canonical_hash(&self) -> Result<[u8; 32], CanonicalError> {
        let proof_hash = self.proof_hash()?;
        canonical_hash(
            KEY_DESTRUCTION_DOMAIN,
            &self.canonical_fields(proof_hash.as_ref()),
        )
    }
}

// ---------------------------------------------------------------------------
// EphemeralContextMetadata (§5.11 durable metadata)
// ---------------------------------------------------------------------------

/// Durable metadata that persists after ephemeral context close.
///
/// Per spec §5.11: "Durable metadata persists: who participated, when, the
/// declared purpose, participation contributions (participation counts,
/// outlet invocations), and discovery provenance."
///
/// Content and messages are NOT included — they are destroyed with the keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EphemeralContextMetadata {
    /// The context identifier.
    pub context_id: ContextId,
    /// DIDs of all participants who were members during the context's
    /// lifetime.
    pub participants: Vec<String>,
    /// Unix timestamp (seconds) when the context was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) when the context was closed/expired.
    pub closed_at: u64,
    /// The declared purpose/description from context params.
    pub purpose: Option<String>,
    /// Per-participant message counts.
    pub participation_counts: HashMap<String, u64>,
    /// Memory scope at close time (always `Ephemeral` for this struct).
    pub memory_scope: super::MemoryScope,
}

// ---------------------------------------------------------------------------
// KeyDestructionResult — DELETED (#2199)
// ---------------------------------------------------------------------------
//
// `KeyDestructionResult` (the `KeyDestructionOrchestrator` return wrapper:
// attestation + relay-deletion requests) was DELETED in #2199 along with the
// dead orchestrators that were its only producers/consumers. The TRUTHFUL
// `KeyDestructionAttestation` is now built inline from the OBSERVED
// `DisposalOutcome` at the actor finalize seam
// (`scp_runtime::context::ttl_close_helpers::finalize_close`);
// `RelayDeletionRequest` (retained below) remains the standalone relay-deletion
// protocol type.

// ---------------------------------------------------------------------------
// RelayDeletionTracker
// ---------------------------------------------------------------------------

/// Tracks relay compliance with deletion requests and deprioritizes
/// non-compliant relays for future context creation.
///
/// Maintains per-relay statistics: total requests, confirmed deletions,
/// partial deletions, failures, and no-responses. Relays with low compliance
/// rates are deprioritized.
///
/// See ADR-018 acceptance criterion 8.
pub struct RelayDeletionTracker {
    /// Per-relay deletion compliance statistics.
    relay_stats: HashMap<String, RelayDeletionStats>,
}

/// Per-relay deletion compliance statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDeletionStats {
    /// Total number of deletion requests sent to this relay.
    pub total_requests: u64,
    /// Number of requests the relay confirmed as fully deleted.
    pub confirmed: u64,
    /// Number of requests the relay partially processed.
    pub partial: u64,
    /// Number of requests the relay failed or rejected.
    pub failed: u64,
    /// Number of requests that received no response.
    pub no_response: u64,
}

impl RelayDeletionStats {
    /// Returns the deletion compliance rate as a value between 0.0 and 1.0.
    ///
    /// A relay with zero total requests returns 1.0 (no evidence of
    /// non-compliance).
    #[must_use]
    pub fn compliance_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 1.0;
        }
        // Ratio of small counts; precision loss is negligible.
        #[allow(clippy::cast_precision_loss)]
        let rate = self.confirmed as f64 / self.total_requests as f64;
        rate
    }
}

impl RelayDeletionTracker {
    /// Creates a new empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            relay_stats: HashMap::new(),
        }
    }

    /// Records a relay's response to a deletion request.
    ///
    /// Increments the appropriate counter for the relay URL based on the
    /// response status.
    pub fn record_response(&mut self, relay_url: &str, response: DeletionResponseStatus) {
        let entry = self.relay_stats.entry(relay_url.to_owned()).or_default();

        entry.total_requests += 1;
        match response {
            DeletionResponseStatus::Confirmed => entry.confirmed += 1,
            DeletionResponseStatus::Partial => entry.partial += 1,
            DeletionResponseStatus::Failed => entry.failed += 1,
            DeletionResponseStatus::NoResponse => entry.no_response += 1,
        }
    }

    /// Returns the compliance statistics for a specific relay.
    ///
    /// Returns `None` if no deletion requests have been tracked for this
    /// relay.
    #[must_use]
    pub fn stats_for_relay(&self, relay_url: &str) -> Option<&RelayDeletionStats> {
        self.relay_stats.get(relay_url)
    }

    /// Returns the compliance rate for a specific relay.
    ///
    /// Returns 1.0 if no deletion requests have been tracked (no evidence
    /// of non-compliance). Returns a value between 0.0 and 1.0 otherwise.
    #[must_use]
    pub fn compliance_rate(&self, relay_url: &str) -> f64 {
        self.relay_stats
            .get(relay_url)
            .map_or(1.0, RelayDeletionStats::compliance_rate)
    }

    /// Returns `true` if the relay should be deprioritized for future
    /// context creation based on its deletion compliance record.
    ///
    /// A relay is deprioritized if its compliance rate is below the given
    /// threshold. The default threshold from ADR-012 is 0.5 (50%).
    #[must_use]
    pub fn is_deprioritized(&self, relay_url: &str, threshold: f64) -> bool {
        self.compliance_rate(relay_url) < threshold
    }

    /// Returns all tracked relay URLs and their compliance stats.
    #[must_use]
    pub const fn all_stats(&self) -> &HashMap<String, RelayDeletionStats> {
        &self.relay_stats
    }

    /// Returns relay URLs sorted by compliance rate (ascending -- worst
    /// compliance first). Useful for selecting relays to deprioritize.
    #[must_use]
    pub fn relays_by_compliance(&self) -> Vec<(&str, f64)> {
        let mut relays: Vec<(&str, f64)> = self
            .relay_stats
            .iter()
            .map(|(url, stats)| (url.as_str(), stats.compliance_rate()))
            .collect();
        relays.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        relays
    }
}

impl Default for RelayDeletionTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Broadcast scope validation
// ---------------------------------------------------------------------------

/// Validates that the memory scope is permitted for the given context mode.
///
/// Broadcast contexts (spec section 5.14) are restricted to
/// `MemoryScope::Full` only. Ephemeral and Summary scopes promise key
/// destruction semantics that broadcast mode cannot deliver, because
/// broadcast mode uses per-author keys without MLS group management and
/// lacks forward secrecy via epoch ratcheting.
///
/// This function should be called at context creation time.
///
/// # Errors
///
/// Returns [`ContextError::InvalidMemoryScopeForBroadcast`] if the context
/// mode is `Broadcast` and the memory scope is `Ephemeral` or `Summary`.
pub fn validate_memory_scope_for_broadcast(
    mode: ContextMode,
    scope: MemoryScope,
) -> Result<(), ContextError> {
    if mode == ContextMode::Broadcast && scope != MemoryScope::Full {
        return Err(ContextError::InvalidMemoryScopeForBroadcast);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::{ContextError, ContextMode, MemoryScope};

    // Note: the runtime-side `KeyDestructionOrchestrator` and its tests were
    // DELETED in #2199 (dead after #2148 moved crypto disposal onto the context
    // actor). The truthful attestation is now built + tested at the actor
    // finalize seam (`scp_runtime::context::ttl_close_helpers::finalize_close`).

    // -----------------------------------------------------------------------
    // KeyDestructionLevel tests
    // -----------------------------------------------------------------------

    #[test]
    fn key_destruction_level_display() {
        assert_eq!(
            format!("{}", KeyDestructionLevel::HardwareAttested),
            "HardwareAttested"
        );
        assert_eq!(
            format!("{}", KeyDestructionLevel::SoftwareOnly),
            "SoftwareOnly"
        );
        assert_eq!(
            format!("{}", KeyDestructionLevel::NoAttestation),
            "NoAttestation"
        );
    }

    #[test]
    fn key_destruction_level_variants_are_distinct() {
        assert_ne!(
            KeyDestructionLevel::HardwareAttested,
            KeyDestructionLevel::SoftwareOnly
        );
        assert_ne!(
            KeyDestructionLevel::SoftwareOnly,
            KeyDestructionLevel::NoAttestation
        );
        assert_ne!(
            KeyDestructionLevel::HardwareAttested,
            KeyDestructionLevel::NoAttestation
        );
    }

    #[test]
    fn key_destruction_level_serialization_roundtrip() {
        let levels = [
            KeyDestructionLevel::HardwareAttested,
            KeyDestructionLevel::SoftwareOnly,
            KeyDestructionLevel::NoAttestation,
        ];
        for level in &levels {
            let json = serde_json::to_string(level).unwrap();
            let deserialized: KeyDestructionLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, level);
        }
    }

    // -----------------------------------------------------------------------
    // RelayDeletionRequest tests
    // -----------------------------------------------------------------------

    #[test]
    fn relay_deletion_request_construction() {
        let blob_id: BlobId = [0xAB; 32];
        let req = RelayDeletionRequest {
            relay_url: "wss://relay.example.com".to_owned(),
            blob_ids: vec![blob_id],
            context_id: "ctx-42".to_owned(),
            requested_at: 1_700_000_000,
        };
        assert_eq!(req.relay_url, "wss://relay.example.com");
        assert_eq!(req.blob_ids.len(), 1);
        assert_eq!(req.blob_ids[0], [0xAB; 32]);
        assert_eq!(req.context_id, "ctx-42");
        assert_eq!(req.requested_at, 1_700_000_000);
    }

    #[test]
    fn relay_deletion_request_serialization_roundtrip() {
        let req = RelayDeletionRequest {
            relay_url: "wss://relay.example.com".to_owned(),
            blob_ids: vec![[0x01; 32], [0x02; 32]],
            context_id: "ctx-99".to_owned(),
            requested_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: RelayDeletionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, req);
    }

    // -----------------------------------------------------------------------
    // RelayDeletionTracker tests
    // -----------------------------------------------------------------------

    #[test]
    fn relay_deletion_tracker_new_is_empty() {
        let tracker = RelayDeletionTracker::new();
        assert!(tracker.all_stats().is_empty());
    }

    #[test]
    fn relay_deletion_tracker_default_is_empty() {
        let tracker = RelayDeletionTracker::default();
        assert!(tracker.all_stats().is_empty());
    }

    #[test]
    fn relay_deletion_tracker_records_confirmed_response() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);

        let stats = tracker.stats_for_relay("wss://relay.example.com").unwrap();
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.confirmed, 1);
        assert_eq!(stats.failed, 0);
    }

    #[test]
    fn relay_deletion_tracker_records_multiple_responses() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Failed);

        let stats = tracker.stats_for_relay("wss://relay.example.com").unwrap();
        assert_eq!(stats.total_requests, 3);
        assert_eq!(stats.confirmed, 2);
        assert_eq!(stats.failed, 1);
    }

    #[test]
    fn relay_deletion_tracker_tracks_all_response_types() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Partial);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Failed);
        tracker.record_response(
            "wss://relay.example.com",
            DeletionResponseStatus::NoResponse,
        );

        let stats = tracker.stats_for_relay("wss://relay.example.com").unwrap();
        assert_eq!(stats.total_requests, 4);
        assert_eq!(stats.confirmed, 1);
        assert_eq!(stats.partial, 1);
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.no_response, 1);
    }

    #[test]
    fn relay_deletion_tracker_unknown_relay_returns_none() {
        let tracker = RelayDeletionTracker::new();
        assert!(
            tracker
                .stats_for_relay("wss://unknown.example.com")
                .is_none()
        );
    }

    #[test]
    fn relay_deletion_tracker_compliance_rate_full_compliance() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);

        let rate = tracker.compliance_rate("wss://relay.example.com");
        assert!((rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn relay_deletion_tracker_compliance_rate_zero_compliance() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Failed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Failed);

        let rate = tracker.compliance_rate("wss://relay.example.com");
        assert!(rate.abs() < f64::EPSILON);
    }

    #[test]
    fn relay_deletion_tracker_compliance_rate_partial() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Failed);

        let rate = tracker.compliance_rate("wss://relay.example.com");
        assert!((rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn relay_deletion_tracker_unknown_relay_compliance_is_1() {
        let tracker = RelayDeletionTracker::new();
        let rate = tracker.compliance_rate("wss://unknown.example.com");
        assert!((rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn relay_deletion_tracker_deprioritized_below_threshold() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Failed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Failed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);

        // compliance_rate = 1/3 ~= 0.333, which is below 0.5
        assert!(tracker.is_deprioritized("wss://relay.example.com", 0.5));
    }

    #[test]
    fn relay_deletion_tracker_not_deprioritized_above_threshold() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://relay.example.com", DeletionResponseStatus::Failed);

        // compliance_rate = 2/3 ~= 0.667, which is above 0.5
        assert!(!tracker.is_deprioritized("wss://relay.example.com", 0.5));
    }

    #[test]
    fn relay_deletion_tracker_unknown_relay_not_deprioritized() {
        let tracker = RelayDeletionTracker::new();
        assert!(!tracker.is_deprioritized("wss://unknown.example.com", 0.5));
    }

    #[test]
    fn relay_deletion_tracker_multiple_relays() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://good.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://good.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://bad.example.com", DeletionResponseStatus::Failed);
        tracker.record_response("wss://bad.example.com", DeletionResponseStatus::Failed);

        assert!((tracker.compliance_rate("wss://good.example.com") - 1.0).abs() < f64::EPSILON);
        assert!(tracker.compliance_rate("wss://bad.example.com").abs() < f64::EPSILON);

        assert!(!tracker.is_deprioritized("wss://good.example.com", 0.5));
        assert!(tracker.is_deprioritized("wss://bad.example.com", 0.5));
    }

    #[test]
    fn relay_deletion_tracker_relays_by_compliance_sorted() {
        let mut tracker = RelayDeletionTracker::new();
        tracker.record_response("wss://good.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://bad.example.com", DeletionResponseStatus::Failed);
        tracker.record_response("wss://mid.example.com", DeletionResponseStatus::Confirmed);
        tracker.record_response("wss://mid.example.com", DeletionResponseStatus::Failed);

        let sorted = tracker.relays_by_compliance();
        assert_eq!(sorted.len(), 3);
        // Worst compliance first.
        assert_eq!(sorted[0].0, "wss://bad.example.com");
        assert!(sorted[0].1.abs() < f64::EPSILON);
        assert_eq!(sorted[1].0, "wss://mid.example.com");
        assert!((sorted[1].1 - 0.5).abs() < f64::EPSILON);
        assert_eq!(sorted[2].0, "wss://good.example.com");
        assert!((sorted[2].1 - 1.0).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // Broadcast scope validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_broadcast_full_scope_succeeds() {
        let result = validate_memory_scope_for_broadcast(ContextMode::Broadcast, MemoryScope::Full);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_broadcast_ephemeral_scope_rejected() {
        let result =
            validate_memory_scope_for_broadcast(ContextMode::Broadcast, MemoryScope::Ephemeral);
        assert!(result.is_err());
        match result {
            Err(ContextError::InvalidMemoryScopeForBroadcast) => {}
            _ => panic!("expected InvalidMemoryScopeForBroadcast error"),
        }
    }

    #[test]
    fn validate_broadcast_summary_scope_rejected() {
        let result =
            validate_memory_scope_for_broadcast(ContextMode::Broadcast, MemoryScope::Summary);
        assert!(result.is_err());
        match result {
            Err(ContextError::InvalidMemoryScopeForBroadcast) => {}
            _ => panic!("expected InvalidMemoryScopeForBroadcast error"),
        }
    }

    #[test]
    fn validate_encrypted_all_scopes_accepted() {
        assert!(
            validate_memory_scope_for_broadcast(ContextMode::Encrypted, MemoryScope::Ephemeral)
                .is_ok()
        );
        assert!(
            validate_memory_scope_for_broadcast(ContextMode::Encrypted, MemoryScope::Summary)
                .is_ok()
        );
        assert!(
            validate_memory_scope_for_broadcast(ContextMode::Encrypted, MemoryScope::Full).is_ok()
        );
    }

    // -----------------------------------------------------------------------
    // KeyDestructionAttestation tests
    // -----------------------------------------------------------------------

    #[test]
    fn key_destruction_attestation_serialization_roundtrip() {
        let attestation = KeyDestructionAttestation {
            context_id: "ctx-1".to_owned(),
            level: KeyDestructionLevel::HardwareAttested,
            attested_at: 1_700_000_000,
            mls_group_destroyed: true,
            sender_keys_destroyed: true,
        };
        let json = serde_json::to_string(&attestation).unwrap();
        let deserialized: KeyDestructionAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, attestation);
    }

    // -----------------------------------------------------------------------
    // RelayDeletionStats tests
    // -----------------------------------------------------------------------

    #[test]
    fn relay_deletion_stats_default_values() {
        let stats = RelayDeletionStats::default();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.confirmed, 0);
        assert_eq!(stats.partial, 0);
        assert_eq!(stats.failed, 0);
        assert_eq!(stats.no_response, 0);
    }

    #[test]
    fn relay_deletion_stats_compliance_rate_no_requests() {
        let stats = RelayDeletionStats::default();
        assert!((stats.compliance_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn relay_deletion_stats_serialization_roundtrip() {
        let stats = RelayDeletionStats {
            total_requests: 10,
            confirmed: 7,
            partial: 1,
            failed: 1,
            no_response: 1,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: RelayDeletionStats = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, stats);
    }

    // -----------------------------------------------------------------------
    // DeletionResponseStatus tests
    // -----------------------------------------------------------------------

    #[test]
    fn deletion_response_status_serialization_roundtrip() {
        let statuses = [
            DeletionResponseStatus::Confirmed,
            DeletionResponseStatus::Partial,
            DeletionResponseStatus::Failed,
            DeletionResponseStatus::NoResponse,
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let deserialized: DeletionResponseStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, status);
        }
    }

    // -----------------------------------------------------------------------
    // DestructionMethod tests (§9.15)
    // -----------------------------------------------------------------------

    #[test]
    fn destruction_method_display() {
        assert_eq!(
            format!("{}", DestructionMethod::HardwareBacked),
            "HardwareBacked"
        );
        assert_eq!(
            format!("{}", DestructionMethod::SoftwareOnly),
            "SoftwareOnly"
        );
    }

    #[test]
    fn destruction_method_variants_are_distinct() {
        assert_ne!(
            DestructionMethod::HardwareBacked,
            DestructionMethod::SoftwareOnly
        );
    }

    #[test]
    fn destruction_method_serialization_roundtrip() {
        let methods = [
            DestructionMethod::HardwareBacked,
            DestructionMethod::SoftwareOnly,
        ];
        for method in &methods {
            let json = serde_json::to_string(method).unwrap();
            let deserialized: DestructionMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, method);
        }
    }

    // -----------------------------------------------------------------------
    // PlatformAttestation tests (§9.15)
    // -----------------------------------------------------------------------

    #[test]
    fn platform_attestation_serialization_roundtrip() {
        let attestation = PlatformAttestation {
            attestation_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            platform: "apple-secure-enclave".to_owned(),
        };
        let json = serde_json::to_string(&attestation).unwrap();
        let deserialized: PlatformAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, attestation);
    }

    // -----------------------------------------------------------------------
    // PublishableKeyDestructionAttestation tests (§9.15)
    // -----------------------------------------------------------------------

    #[test]
    fn publishable_attestation_serialization_roundtrip() {
        let attestation = PublishableKeyDestructionAttestation {
            context_id: "ctx-42".to_owned(),
            member_did: "did:dht:alice".to_owned(),
            destroyed_at: 1_700_000_000,
            platform_attestation: Some(PlatformAttestation {
                attestation_data: vec![0x01, 0x02],
                platform: "android-keystore".to_owned(),
            }),
            method: DestructionMethod::HardwareBacked,
            signing_key_id: DestructionSignerKeyId::Active,
            signature: vec![0xAA; 64],
        };
        let json = serde_json::to_string(&attestation).unwrap();
        let deserialized: PublishableKeyDestructionAttestation =
            serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, attestation);
    }

    #[test]
    fn publishable_attestation_valid_signature_length() {
        let attestation = PublishableKeyDestructionAttestation {
            context_id: "ctx-1".to_owned(),
            member_did: "did:dht:bob".to_owned(),
            destroyed_at: 1_700_000_000,
            platform_attestation: None,
            method: DestructionMethod::SoftwareOnly,
            signing_key_id: DestructionSignerKeyId::Active,
            signature: vec![0x00; 64],
        };
        assert!(attestation.has_valid_signature_length());
    }

    #[test]
    fn publishable_attestation_invalid_signature_length() {
        let attestation = PublishableKeyDestructionAttestation {
            context_id: "ctx-1".to_owned(),
            member_did: "did:dht:bob".to_owned(),
            destroyed_at: 1_700_000_000,
            platform_attestation: None,
            method: DestructionMethod::SoftwareOnly,
            signing_key_id: DestructionSignerKeyId::Active,
            signature: vec![0x00; 32], // Wrong length
        };
        assert!(!attestation.has_valid_signature_length());
    }

    #[test]
    fn publishable_attestation_signing_preimage_deterministic() {
        let attestation = PublishableKeyDestructionAttestation {
            context_id: "ctx-1".to_owned(),
            member_did: "did:dht:alice".to_owned(),
            destroyed_at: 1_700_000_000,
            platform_attestation: None,
            method: DestructionMethod::SoftwareOnly,
            signing_key_id: DestructionSignerKeyId::Active,
            signature: vec![0x00; 64],
        };
        let preimage1 = attestation.signing_preimage().unwrap();
        let preimage2 = attestation.signing_preimage().unwrap();
        assert_eq!(preimage1, preimage2);
        // 23-byte domain + (4 + 5) context_id + (4 + 13) member_did
        // + 8 destroyed_at + 32 proof sentinel + 1 method + (4 + 7) key id.
        assert_eq!(preimage1.len(), 101);
    }

    #[test]
    fn publishable_attestation_canonical_hash_covers_the_preimage() {
        use sha2::{Digest, Sha256};
        let attestation = PublishableKeyDestructionAttestation {
            context_id: "ctx-1".to_owned(),
            member_did: "did:dht:alice".to_owned(),
            destroyed_at: 1_700_000_000,
            platform_attestation: None,
            method: DestructionMethod::SoftwareOnly,
            signing_key_id: DestructionSignerKeyId::Active,
            signature: vec![0x00; 64],
        };
        let expected: [u8; 32] = Sha256::digest(attestation.signing_preimage().unwrap()).into();
        assert_eq!(attestation.canonical_hash().unwrap(), expected);
    }

    #[test]
    fn destruction_method_discriminators_match_the_spec_row() {
        // §9.5.2 of the security spec assigns 0x00 to the lower-confidence
        // variant, so a zero-filled byte decodes to the weaker claim.
        assert_eq!(DestructionMethod::SoftwareOnly.discriminator(), 0x00);
        assert_eq!(DestructionMethod::HardwareBacked.discriminator(), 0x01);
    }

    #[test]
    fn publishable_attestation_no_platform_attestation_for_software_only() {
        let attestation = PublishableKeyDestructionAttestation {
            context_id: "ctx-1".to_owned(),
            member_did: "did:dht:carol".to_owned(),
            destroyed_at: 1_700_000_000,
            platform_attestation: None,
            method: DestructionMethod::SoftwareOnly,
            signing_key_id: DestructionSignerKeyId::Active,
            signature: vec![0xFF; 64],
        };
        assert!(attestation.platform_attestation.is_none());
        assert_eq!(
            attestation.verified_method(),
            DestructionMethod::SoftwareOnly
        );
    }

    // -----------------------------------------------------------------------
    // EphemeralContextMetadata tests (§5.11)
    // -----------------------------------------------------------------------

    #[test]
    fn ephemeral_metadata_serialization_roundtrip() {
        let mut counts = HashMap::new();
        counts.insert("did:dht:alice".to_owned(), 15);
        counts.insert("did:dht:bob".to_owned(), 8);
        let metadata = EphemeralContextMetadata {
            context_id: "ctx-ephemeral".to_owned(),
            participants: vec!["did:dht:alice".to_owned(), "did:dht:bob".to_owned()],
            created_at: 1_700_000_000,
            closed_at: 1_700_001_000,
            purpose: Some("Quick brainstorm".to_owned()),
            participation_counts: counts,
            memory_scope: crate::context::MemoryScope::Ephemeral,
        };
        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: EphemeralContextMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, metadata);
    }

    #[test]
    fn ephemeral_metadata_preserves_participants_after_creation() {
        let metadata = EphemeralContextMetadata {
            context_id: "ctx-1".to_owned(),
            participants: vec![
                "did:dht:alice".to_owned(),
                "did:dht:bob".to_owned(),
                "did:dht:carol".to_owned(),
            ],
            created_at: 1_700_000_000,
            closed_at: 1_700_000_300,
            purpose: None,
            participation_counts: HashMap::new(),
            memory_scope: crate::context::MemoryScope::Ephemeral,
        };
        // Verify all participants are preserved.
        assert_eq!(metadata.participants.len(), 3);
        assert!(metadata.participants.contains(&"did:dht:alice".to_owned()));
        assert!(metadata.participants.contains(&"did:dht:bob".to_owned()));
        assert!(metadata.participants.contains(&"did:dht:carol".to_owned()));
        // Creation time is preserved.
        assert_eq!(metadata.created_at, 1_700_000_000);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod destruction_reading_rule_tests {
    //! §27.4.6 of `.docs/specs/27-attestations.md` quotes a human ruling of
    //! 2026-08-25 and states it in four clauses: a hardware-backed declaration
    //! reads as software-backed unless a verified platform attestation proof
    //! accompanies it. No verification of such a proof exists in any SCP
    //! implementation, so every hardware declaration reads as `SoftwareOnly`.
    //!
    //! The tests below also pin what the signed scope does: §9.5.2 of the
    //! security spec carries `platform_attestation` in the preimage, so
    //! stripping the proof or substituting another one breaks the signature.

    use super::{
        DestructionMethod, DestructionSignerKeyId, PlatformAttestation,
        PublishableKeyDestructionAttestation,
    };

    fn attestation(
        method: DestructionMethod,
        proof: Option<PlatformAttestation>,
    ) -> PublishableKeyDestructionAttestation {
        PublishableKeyDestructionAttestation::new(
            "ctx-ruling".to_owned(),
            "did:dht:alice".to_owned(),
            1_700_000_000,
            proof,
            method,
            DestructionSignerKeyId::Active,
            vec![0xAA; 64],
        )
    }

    #[test]
    fn a_hardware_declaration_without_a_proof_reads_as_software_only() {
        let a = attestation(DestructionMethod::HardwareBacked, None);
        assert_eq!(a.verified_method(), DestructionMethod::SoftwareOnly);
    }

    #[test]
    fn an_attached_but_unverified_proof_does_not_raise_the_reading() {
        // Clause 1 admits a hardware reading only when a verification returns a
        // pass. Attaching bytes is not a verification.
        let proof = PlatformAttestation {
            attestation_data: vec![0xAB; 64],
            platform: "apple-secure-enclave".to_owned(),
        };
        let a = attestation(DestructionMethod::HardwareBacked, Some(proof));
        assert_eq!(a.verified_method(), DestructionMethod::SoftwareOnly);
    }

    #[test]
    fn a_software_declaration_reads_as_software_only_and_needs_no_proof() {
        let a = attestation(DestructionMethod::SoftwareOnly, None);
        assert_eq!(a.verified_method(), DestructionMethod::SoftwareOnly);
    }

    #[test]
    fn stripping_the_proof_changes_the_signed_bytes() {
        // Contradiction C34 said the signature bound the declaration and left
        // the proof detachable. §9.5.2 of the security spec now places
        // `platform_attestation` in the preimage, so a holder who strips it
        // changes the hash a signature covers and that signature no longer
        // verifies. The predecessor of this test asserted the two preimages
        // equal, and it fails against this body.
        let proof = PlatformAttestation {
            attestation_data: vec![0xCD; 8],
            platform: "android-keystore".to_owned(),
        };
        let with_proof = attestation(DestructionMethod::HardwareBacked, Some(proof));
        let without_proof = attestation(DestructionMethod::HardwareBacked, None);
        assert_ne!(
            with_proof.signing_preimage().unwrap(),
            without_proof.signing_preimage().unwrap()
        );
        assert_ne!(
            with_proof.canonical_hash().unwrap(),
            without_proof.canonical_hash().unwrap()
        );
    }

    #[test]
    fn swapping_in_a_different_proof_changes_the_signed_bytes() {
        let apple = PlatformAttestation {
            attestation_data: vec![0xCD; 8],
            platform: "apple-secure-enclave".to_owned(),
        };
        let android = PlatformAttestation {
            attestation_data: vec![0xCD; 8],
            platform: "android-keystore".to_owned(),
        };
        let signed = attestation(DestructionMethod::HardwareBacked, Some(apple));
        let swapped = attestation(DestructionMethod::HardwareBacked, Some(android));
        assert_ne!(
            signed.canonical_hash().unwrap(),
            swapped.canonical_hash().unwrap()
        );

        // The same platform with different proof bytes is a different record too.
        let mutated_bytes = PlatformAttestation {
            attestation_data: vec![0xCE; 8],
            platform: "apple-secure-enclave".to_owned(),
        };
        let mutated = attestation(DestructionMethod::HardwareBacked, Some(mutated_bytes));
        assert_ne!(
            signed.canonical_hash().unwrap(),
            mutated.canonical_hash().unwrap()
        );
    }

    #[test]
    fn a_stripped_proof_fails_ed25519_verification() {
        use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

        let proof = PlatformAttestation {
            attestation_data: vec![0xCD; 8],
            platform: "apple-secure-enclave".to_owned(),
        };
        let signer = SigningKey::from_bytes(&[0x11; 32]);
        let verifier: VerifyingKey = signer.verifying_key();

        let mut record = attestation(DestructionMethod::HardwareBacked, Some(proof));
        let signature = signer.sign(&record.canonical_hash().unwrap());
        record.signature = signature.to_bytes().to_vec();
        verifier
            .verify(&record.canonical_hash().unwrap(), &signature)
            .expect("the record the signer signed must verify");

        // A holder strips the proof and presents the same signature.
        record.platform_attestation = None;
        assert!(
            verifier
                .verify(&record.canonical_hash().unwrap(), &signature)
                .is_err(),
            "a stripped proof must invalidate the signature"
        );
    }

    #[test]
    fn the_signed_bytes_bind_the_declared_method_and_the_signing_key_id() {
        let hardware = attestation(DestructionMethod::HardwareBacked, None);
        let software = attestation(DestructionMethod::SoftwareOnly, None);
        assert_ne!(
            hardware.canonical_hash().unwrap(),
            software.canonical_hash().unwrap()
        );

        let mut other_key = attestation(DestructionMethod::SoftwareOnly, None);
        other_key.signing_key_id = DestructionSignerKeyId::Identity;
        assert_ne!(
            software.canonical_hash().unwrap(),
            other_key.canonical_hash().unwrap()
        );
    }

    #[test]
    fn the_declaration_still_round_trips_on_the_wire() {
        // The gate governs what a consumer reads. It does not rewrite what a
        // publisher wrote, because a republished record must carry the
        // publisher's own declaration unchanged.
        let a = attestation(DestructionMethod::HardwareBacked, None);
        let json = serde_json::to_string(&a).unwrap();
        assert!(json.contains("HardwareBacked"));
        let back: PublishableKeyDestructionAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
        assert_eq!(back.verified_method(), DestructionMethod::SoftwareOnly);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod destruction_test_vectors {
    //! §25.25 of `.docs/specs/25-test-vectors.md` pins Vector 38 and Vector 39,
    //! the two known-answer vectors for the key-destruction signing preimage.
    //! Vector 38 carries no platform attestation proof and Vector 39 carries
    //! one, so the pair pins both arms of §9.5.1's optional-field rule. Two
    //! conforming implementations that disagree on a byte fail here.

    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

    use super::{
        DESTRUCTION_PROOF_DOMAIN, DestructionMethod, DestructionSignerKeyId,
        KEY_DESTRUCTION_DOMAIN, PlatformAttestation, PublishableKeyDestructionAttestation,
    };

    /// The §25.2 reference Ed25519 seed — RFC 8032 §7.1 Test Vector 1.
    const REF_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    /// The §25.2 reference Ed25519 public key.
    const REF_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    const CONTEXT_ID: &str = "ctx-destroy-vector";
    const MEMBER_DID: &str = "did:dht:z6MkDestroyer";
    const DESTROYED_AT: u64 = 1_700_000_000;
    const SIGNING_KEY_ID: DestructionSignerKeyId = DestructionSignerKeyId::Active;

    fn record(
        method: DestructionMethod,
        proof: Option<PlatformAttestation>,
    ) -> PublishableKeyDestructionAttestation {
        PublishableKeyDestructionAttestation::new(
            CONTEXT_ID.to_owned(),
            MEMBER_DID.to_owned(),
            DESTROYED_AT,
            proof,
            method,
            SIGNING_KEY_ID,
            vec![0x00; 64],
        )
    }

    /// The Vector 39 proof: eight bytes of attestation data from an Apple
    /// Secure Enclave.
    fn vector_39_proof() -> PlatformAttestation {
        PlatformAttestation {
            attestation_data: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            platform: "apple-secure-enclave".to_owned(),
        }
    }

    fn signed(record: &PublishableKeyDestructionAttestation) -> [u8; 64] {
        SigningKey::from_bytes(&REF_SEED)
            .sign(&record.canonical_hash().unwrap())
            .to_bytes()
    }

    #[test]
    fn the_reference_key_reproduces_the_spec_public_key() {
        // §25.2 states that an implementation failing this check has a broken
        // Ed25519 and must not proceed with interoperability testing.
        let public = SigningKey::from_bytes(&REF_SEED).verifying_key();
        assert_eq!(hex::encode(public.as_bytes()), REF_PUBLIC);
    }

    #[test]
    fn the_signing_key_id_serializes_as_the_fragment_the_spec_states() {
        // §9.15 of the security spec states the value domain as `"#0" | "#active"`,
        // and field 6 of the §9.5.2 preimage carries those same bytes. A derived
        // `Serialize` would emit the variant name instead, so the wire alphabet and
        // the preimage alphabet would differ.
        let json = serde_json::to_string(&DestructionSignerKeyId::Active).unwrap();
        assert_eq!(json, "\"#active\"");
        let json = serde_json::to_string(&DestructionSignerKeyId::Identity).unwrap();
        assert_eq!(json, "\"#0\"");

        let back: DestructionSignerKeyId = serde_json::from_str("\"#0\"").unwrap();
        assert_eq!(back, DestructionSignerKeyId::Identity);

        // Everything outside the permitted set is rejected on the wire, including
        // the variant names a derived implementation would have accepted.
        for rejected in ["#agent", "", "Active", "Identity", "#ACTIVE", "active"] {
            let encoded = serde_json::to_string(rejected).unwrap();
            assert!(
                serde_json::from_str::<DestructionSignerKeyId>(&encoded).is_err(),
                "{rejected:?} must not deserialize"
            );
        }
    }

    #[test]
    fn field_six_carries_the_identity_fragment_as_two_bytes() {
        // No known-answer vector pins the `#0` arm, because §25.25 uses `"#active"`
        // in both vectors — the one fragment both sides of contradiction C35 admit.
        // This test pins the other arm's bytes.
        let mut attestation = record(DestructionMethod::SoftwareOnly, None);
        attestation.signing_key_id = DestructionSignerKeyId::Identity;
        let preimage = attestation.signing_preimage().unwrap();
        // 122 bytes minus the 5-byte difference between "#active" and "#0".
        assert_eq!(preimage.len(), 117);
        // BE32(2) || "#0" == 00000002 2330
        assert!(hex::encode(&preimage).ends_with("000000022330"));
    }

    #[test]
    fn the_domain_separators_match_the_registry_rows() {
        // §9.18.2 of the security spec registers both strings.
        assert_eq!(KEY_DESTRUCTION_DOMAIN, "SCP-KEY-DESTRUCTION-V2:");
        assert_eq!(DESTRUCTION_PROOF_DOMAIN, "SCP-DESTRUCTION-PROOF-V1:");
    }

    #[test]
    fn vector_38_pins_the_preimage_hash_and_signature_with_no_proof() {
        let attestation = record(DestructionMethod::SoftwareOnly, None);

        let preimage = attestation.signing_preimage().unwrap();
        assert_eq!(preimage.len(), 122);
        assert_eq!(
            hex::encode(&preimage),
            concat!(
                "5343502d4b45592d4445535452554354494f4e2d56323a",
                "000000126374782d64657374726f792d766563746f72",
                "000000156469643a6468743a7a364d6b44657374726f796572",
                "000000006553f100",
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                "00",
                "0000000723616374697665",
            )
        );

        let hash = attestation.canonical_hash().unwrap();
        assert_eq!(
            hex::encode(hash),
            "8a140aac6b15748b96cef6cfb1942bc0b1b68ecbc505ac8de487452ba18ba7c4"
        );

        let signature = signed(&attestation);
        assert_eq!(
            hex::encode(signature),
            concat!(
                "63df30675677a88898ce9e6ddd95de1df080efb03b21c58a7de4886ccdbd53b7",
                "e216826ffa797a124fbfe8fc81262fd06e3b45e5edb2ec4526475fcb829f6c0d",
            )
        );

        SigningKey::from_bytes(&REF_SEED)
            .verifying_key()
            .verify(&hash, &Signature::from_bytes(&signature))
            .expect("Vector 38 signature must verify under the reference key");
    }

    #[test]
    fn vector_39_pins_the_preimage_hash_and_signature_with_a_proof() {
        let proof = vector_39_proof();
        assert_eq!(
            hex::encode(proof.proof_hash().unwrap()),
            "743ccc956ebe5f89a1ba4c0c8a6caae5361c7c7e6e7c78d31821e139ed16096e"
        );

        let attestation = record(DestructionMethod::HardwareBacked, Some(proof));

        let preimage = attestation.signing_preimage().unwrap();
        assert_eq!(preimage.len(), 122);
        assert_eq!(
            hex::encode(&preimage),
            concat!(
                "5343502d4b45592d4445535452554354494f4e2d56323a",
                "000000126374782d64657374726f792d766563746f72",
                "000000156469643a6468743a7a364d6b44657374726f796572",
                "000000006553f100",
                "743ccc956ebe5f89a1ba4c0c8a6caae5361c7c7e6e7c78d31821e139ed16096e",
                "01",
                "0000000723616374697665",
            )
        );

        let hash = attestation.canonical_hash().unwrap();
        assert_eq!(
            hex::encode(hash),
            "6a6a896cd7c711b6cbfaab276e7de891bc9fdb5bb9ce1826b288fa3e69e9ccb1"
        );

        let signature = signed(&attestation);
        assert_eq!(
            hex::encode(signature),
            concat!(
                "6b7c14cd04ab2b757fd2e37f70637879ddc4af55b4c19f54f653f2b7dbe4bf42",
                "81d44646053f53b5b100c2d2e572ac31a0a7ae58f491baebcf57a41743ae960b",
            )
        );

        SigningKey::from_bytes(&REF_SEED)
            .verifying_key()
            .verify(&hash, &Signature::from_bytes(&signature))
            .expect("Vector 39 signature must verify under the reference key");
    }

    #[test]
    fn the_vector_39_signature_rejects_the_vector_38_record() {
        // The two vectors differ in the method byte and in the proof field, so
        // neither signature covers the other record.
        let with_proof = record(DestructionMethod::HardwareBacked, Some(vector_39_proof()));
        let without_proof = record(DestructionMethod::SoftwareOnly, None);
        let signature = Signature::from_bytes(&signed(&with_proof));
        assert!(
            SigningKey::from_bytes(&REF_SEED)
                .verifying_key()
                .verify(&without_proof.canonical_hash().unwrap(), &signature)
                .is_err()
        );
    }
}
