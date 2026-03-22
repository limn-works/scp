//! Inner envelope creation, signing, and verification.
//!
//! The inner envelope is the authenticated payload visible only to group
//! members after MLS decryption. It carries the sender's DID, sequence
//! numbers, timestamp, the padded payload, provenance metadata, and an
//! Ed25519 signature over a hash of all critical fields.
//!
//! **Processing order:** hash original plaintext -> hash provenance -> sign
//! (covering both hashes) -> pad payload to bucket boundary.
//!
//! The signature covers the *original* payload hash (before padding), so
//! verification must use `payload_hash` rather than re-hashing the padded
//! payload.
//!
//! See ADR-002 acceptance criteria 2 and 6 in `.docs/adrs/phase-1.md`.
//!
//! # Modules
//!
//! - [`sign`] — Async inner envelope creation (calls `KeyCustody::sign`).

pub mod sign;

pub use sign::create_inner_envelope;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::EnvelopeError;
use crate::identity::SigningKeyId;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Provenance metadata attached to an inner envelope.
///
/// The type of message carried in the inner envelope.
///
/// Used as a discriminator byte in the canonical hash to prevent type-flipping
/// attacks (changing a content message to a signaling message after signing).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Regular content message (chat, tool output, etc.).
    #[default]
    Content,

    /// WebRTC signaling message (SDP offer/answer, ICE candidate).
    Signaling,

    /// Sender key distribution sub-protocol message (§9.16).
    ///
    /// The payload is a MessagePack-serialized
    /// [`SenderKeyDistributionMessage`](crate::crypto::sender_keys::key_protocol::SenderKeyDistributionMessage)
    /// carrying epoch advances, key requests, key responses, or block
    /// notifications. This discriminator allows the transport layer to route
    /// sender key protocol messages through the existing envelope pipeline
    /// without adding new transport-level operations.
    KeyDistribution,
}

impl MessageType {
    /// Returns a single-byte discriminator for inclusion in canonical hashes.
    #[must_use]
    pub const fn as_discriminator_byte(&self) -> u8 {
        match self {
            Self::Content => 0,
            Self::Signaling => 1,
            Self::KeyDistribution => 2,
        }
    }
}

/// Provenance tracks the origin of message content.
///
/// Records which tool generated it, which agent produced it, and any upstream
/// references. The exact structure will be expanded in later phases; this
/// provides a serializable placeholder. See spec section 7.7 for the full
/// provenance model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Human-readable description of the content origin.
    /// Bounded to 1 KiB on deserialization to prevent OOM (#347).
    #[serde(with = "crate::serde_util::serde_bounded_string")]
    pub source: String,
    /// Optional upstream content hash for chain-of-custody tracking.
    /// Bounded to 1 KiB on deserialization to prevent OOM (#347).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::serde_util::serde_bounded_string_opt"
    )]
    pub upstream_hash: Option<String>,
}

/// The inner envelope — the authenticated, encrypted payload visible only to
/// MLS group members after decryption.
///
/// All fields are serialized with `MessagePack` via `rmp-serde`. Binary fields
/// use `serde_bytes` for efficient `MessagePack` binary encoding.
/// The current SCP protocol version for inner envelopes.
///
/// See spec §13.2 for the version encoding scheme: `(major << 8) | minor`.
/// SCP/1.0 = `0x0100` (decimal 256).
pub const SCP_INNER_ENVELOPE_VERSION: u16 = super::SCP_PROTOCOL_VERSION;

/// Serde default for the `version` field on [`InnerEnvelope`].
const fn default_inner_version() -> u16 {
    SCP_INNER_ENVELOPE_VERSION
}

/// The authenticated inner envelope visible only to MLS group members.
///
/// Carries the sender's DID, sequence numbers, timestamp, padded payload,
/// provenance metadata, and an Ed25519 signature over a canonical hash of
/// all critical fields (spec §13.2.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnerEnvelope {
    /// Protocol version (§13.2.1). SCP/1.0 = `0x0100`.
    /// Part of the signature commitment — changing this changes the signed bytes.
    #[serde(default = "default_inner_version")]
    pub version: u16,

    /// The SCP context identifier.
    /// Bounded to 1 KiB on deserialization to prevent OOM (#347).
    #[serde(with = "crate::serde_util::serde_bounded_string")]
    pub context_id: String,

    /// The sender's full DID.
    /// Bounded to 1 KiB on deserialization to prevent OOM (#347).
    #[serde(with = "crate::serde_util::serde_bounded_string")]
    pub sender_did: String,

    /// MLS epoch number.
    pub epoch: u64,

    /// MLS generation number.
    pub generation: u64,

    /// SCP per-sender monotonic sequence number.
    pub sequence: u64,

    /// Creation timestamp (Unix milliseconds).
    pub timestamp: u64,

    /// The type of message (content vs. signaling). Included in the canonical
    /// hash to prevent type-flipping attacks. Defaults to `Content` for
    /// backward compatibility with envelopes created before this field was
    /// added.
    #[serde(default)]
    pub message_type: MessageType,

    /// SHA-256 hash of the original plaintext payload (before padding).
    #[serde(with = "crate::serde_util::serde_hash_32")]
    pub payload_hash: [u8; 32],

    /// The message payload (after bucket padding).
    /// Bounded to 512 KiB on deserialization to prevent OOM (#347).
    ///
    /// **Interaction with `#[serde(flatten)]` on `extensions`:** When
    /// `flatten` is present, serde buffers all map entries before dispatching
    /// to field deserializers. This means `serde_bounded_bytes` fires *after*
    /// the full input has been buffered into memory. Callers that deserialize
    /// untrusted bytes should apply an upfront size check before calling
    /// `rmp_serde::from_slice`; `serde_bounded_bytes` acts as
    /// defense-in-depth for the individual field.
    #[serde(with = "crate::serde_util::serde_bounded_bytes")]
    pub payload: Vec<u8>,

    /// Optional provenance metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,

    /// SHA-256 hash of the serialized provenance (or SHA-256(0x00) if absent).
    #[serde(with = "crate::serde_util::serde_hash_32")]
    pub provenance_hash: [u8; 32],

    /// Identifies which DID verification method (`#active` or `#agent`)
    /// produced the signature. Defaults to `Active` for backward compatibility
    /// with envelopes created before agent binding (ADR-039).
    #[serde(default)]
    pub signing_key_id: SigningKeyId,

    /// Ed25519 signature over the canonical hash of all critical fields.
    #[serde(with = "crate::serde_util::serde_signature_64")]
    pub signature: [u8; 64],

    /// Forward-compatibility extensions — unknown fields from future protocol
    /// versions are preserved here for forward-compatible roundtripping
    /// (§13.5.1). Intermediaries and SDK storage layers that deserialize and
    /// re-serialize inner envelopes MUST NOT strip unrecognized fields.
    /// Excluded from canonical hash computation and signing.
    ///
    /// Uses `rmpv::Value` (not `serde_json::Value`) to preserve `MessagePack`
    /// type fidelity. A `MsgPack` Binary field roundtrips as Binary; with
    /// `serde_json::Value` it would degrade to an Array of numbers — silent
    /// data corruption.
    ///
    /// **Security note:** Extensions carry no authenticity guarantee. Fields
    /// in this map are not covered by the envelope signature. Do not use
    /// extension values for security-sensitive decisions.
    #[serde(flatten)]
    pub extensions: HashMap<String, rmpv::Value>,
}

impl InnerEnvelope {
    /// Deserializes an `InnerEnvelope` from `MessagePack` bytes with a
    /// pre-deserialization size check.
    ///
    /// The size check rejects inputs exceeding [`MAX_ENVELOPE_SIZE`] *before*
    /// invoking the deserializer, preventing `serde`'s `#[serde(flatten)]`
    /// buffering from allocating memory for oversized inputs. This mirrors
    /// [`OuterEnvelope::from_bytes`](super::outer::OuterEnvelope::from_bytes).
    ///
    /// [`MAX_ENVELOPE_SIZE`]: crate::serde_util::MAX_ENVELOPE_SIZE
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::EnvelopeTooLarge`] if `data.len()` exceeds
    /// `MAX_ENVELOPE_SIZE`.
    /// Returns [`EnvelopeError::DeserializationFailed`] if the bytes are not
    /// a valid `MessagePack`-encoded `InnerEnvelope`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, EnvelopeError> {
        use crate::serde_util::MAX_ENVELOPE_SIZE;

        if data.len() > MAX_ENVELOPE_SIZE {
            return Err(EnvelopeError::EnvelopeTooLarge {
                size: data.len(),
                max: MAX_ENVELOPE_SIZE,
            });
        }
        rmp_serde::from_slice(data).map_err(|e| EnvelopeError::DeserializationFailed(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Params
// ---------------------------------------------------------------------------

/// Parameters for inner envelope creation.
///
/// Groups the data fields that describe the envelope content, separating them
/// from the cryptographic primitives (`key_custody`, `signing_key`) passed
/// alongside. This eliminates the four consecutive `u64` parameters that were
/// easy to accidentally transpose.
#[derive(Debug, Clone)]
pub struct InnerEnvelopeParams<'a> {
    /// Protocol version (§13.2.1). Use [`SCP_INNER_ENVELOPE_VERSION`] for
    /// current protocol version.
    pub version: u16,
    /// The SCP context identifier.
    pub context_id: &'a str,
    /// The sender's full DID.
    pub sender_did: &'a str,
    /// MLS epoch number.
    pub epoch: u64,
    /// MLS generation number.
    pub generation: u64,
    /// SCP per-sender monotonic sequence number.
    pub sequence: u64,
    /// Creation timestamp (Unix milliseconds).
    pub timestamp: u64,
    /// The type of message (content vs. signaling). Included in the canonical
    /// hash to prevent type-flipping attacks (issue #290).
    pub message_type: MessageType,
    /// The message payload (before padding).
    pub payload: &'a [u8],
    /// Optional provenance metadata.
    pub provenance: Option<Provenance>,
    /// Which DID verification method produced the signature.
    /// Defaults to `Active` for backward compatibility.
    pub signing_key_id: SigningKeyId,
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verifies the Ed25519 inner signature of an envelope against a sender's
/// public key.
///
/// Recomputes the canonical hash from the envelope's fields (using the stored
/// `payload_hash`, not the padded payload) and verifies the signature.
///
/// **Key resolution:** Callers must inspect `inner.signing_key_id` to
/// determine which verification method public key to pass as
/// `sender_public_key`. For [`SigningKeyId::Active`], use the `#active`
/// verification method. For [`SigningKeyId::Agent`], use the `#agent`
/// verification method from the sender's DID document.
///
/// # Errors
///
/// Returns [`EnvelopeError::VerificationFailed`] if the public key or
/// signature bytes are malformed. Returns `Ok(false)` if the signature is
/// well-formed but does not match.
pub fn verify_inner_signature(
    inner: &InnerEnvelope,
    sender_public_key: &[u8],
) -> Result<bool, EnvelopeError> {
    // Recompute the provenance hash from the stored provenance.
    let provenance_hash = compute_provenance_hash(inner.provenance.as_ref())
        .map_err(|e| EnvelopeError::VerificationFailed(e.to_string()))?;

    // Reject incompatible major versions before signature verification (§13.5).
    // Same-major envelopes with different minor versions proceed in degraded
    // mode — the canonical hash uses the wire version, so signature
    // verification works across minor version differences.
    let compat = super::check_version_compatibility(inner.version)?;
    if let super::VersionCompatibility::DegradedMode {
        local_minor,
        remote_minor,
    } = compat
    {
        tracing::warn!(
            wire_version = format_args!("{:#06x}", inner.version),
            local_version = format_args!("{:#06x}", super::SCP_PROTOCOL_VERSION),
            local_minor,
            remote_minor,
            "inner envelope minor version mismatch during signature verification — \
             operating in degraded mode (§13.6)"
        );
    }

    // Reconstruct params for canonical hash computation.
    let params = InnerEnvelopeParams {
        version: inner.version,
        context_id: &inner.context_id,
        sender_did: &inner.sender_did,
        epoch: inner.epoch,
        generation: inner.generation,
        sequence: inner.sequence,
        timestamp: inner.timestamp,
        message_type: inner.message_type,
        payload: &[],
        provenance: inner.provenance.clone(),
        signing_key_id: inner.signing_key_id,
    };

    // Recompute the canonical hash. payload_hash and provenance_hash are
    // already validated as [u8; 32] by serde deserialization.
    // The version from the envelope is used (not the constant) so that
    // tampering with the version field causes verification to fail (§13.2.1).
    let canonical_hash = compute_canonical_hash(&params, &inner.payload_hash, &provenance_hash);

    // Verify using strict mode (rejects small-order points).
    match crate::crypto::ed25519::verify_ed25519_signature(
        sender_public_key,
        &canonical_hash,
        &inner.signature,
    ) {
        Ok(()) => Ok(true),
        Err(reason) => {
            // Signature mismatch -> Ok(false). Malformed inputs -> Err.
            // Match the known verification-failure prefix so unknown errors
            // default to Err (safe) rather than Ok(false) (silent suppression).
            if reason.starts_with("signature verification failed") {
                Ok(false)
            } else {
                Err(EnvelopeError::VerificationFailed(reason))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Category A enforcement (ADR-039, SCP-AB-020)
// ---------------------------------------------------------------------------

/// Enforces Category A restrictions on a verified inner envelope.
///
/// Call this **after** [`verify_inner_signature`] returns `Ok(true)`. If the
/// envelope's `signing_key_id` is [`SigningKeyId::Agent`] and the
/// `action_resource` is a Category A resource (DID document modification),
/// returns `Err` with the violation details. The caller should reject the
/// envelope and optionally persist/broadcast the custody violation
/// attestation.
///
/// For Category B actions or Active-key signatures, returns `Ok(())`.
///
/// # Arguments
///
/// * `inner` — The verified inner envelope.
/// * `action_resource` — The UCAN capability resource type of the action
///   this envelope carries (e.g., `"messages"`, `"did_document"`). This is
///   determined by the caller from the application-layer context.
///
/// # Errors
///
/// Returns [`EnvelopeError::CategoryAViolation`] if an agent key attempted
/// a DID document modification.
pub fn enforce_inner_envelope_category_a(
    inner: &InnerEnvelope,
    action_resource: &str,
) -> Result<(), EnvelopeError> {
    use crate::trust::custody_violation::{classify_action, enforce_category_a};

    let category = classify_action(action_resource);
    if let Err(violation) = enforce_category_a(
        inner.signing_key_id,
        category,
        &inner.sender_did,
        &format!("inner envelope action: {action_resource}"),
        &inner.signature,
    ) {
        return Err(EnvelopeError::CategoryAViolation(violation.error_message));
    }

    Ok(())
}

/// Validates that an inner envelope's version field is compatible (§13.5).
///
/// Accepts envelopes with the same major version. Returns
/// `VersionCompatibility` so the caller can decide whether and how to log
/// degraded-mode situations. This function intentionally does **not** emit
/// `tracing::warn!` itself, because [`verify_inner_signature`] also calls
/// [`check_version_compatibility`](super::check_version_compatibility) and
/// logs on mismatch — callers that invoke both would otherwise get duplicate
/// warnings.
///
/// # Errors
///
/// Returns [`EnvelopeError::UnsupportedVersion`] if the major version differs
/// from this implementation's major version.
pub const fn validate_inner_version(
    inner: &InnerEnvelope,
) -> Result<super::VersionCompatibility, EnvelopeError> {
    super::check_version_compatibility(inner.version)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Computes `SHA-256(serialize(provenance))` if present, or `SHA-256(0x00)` if
/// absent. Returns a fixed-size 32-byte array (SHA-256 output).
pub(crate) fn compute_provenance_hash(
    provenance: Option<&Provenance>,
) -> Result<[u8; 32], EnvelopeError> {
    match provenance {
        Some(p) => {
            let serialized = rmp_serde::to_vec(p)
                .map_err(|e| EnvelopeError::SerializationFailed(e.to_string()))?;
            Ok(Sha256::digest(&serialized).into())
        }
        None => Ok(Sha256::digest([0x00]).into()),
    }
}

/// Computes the canonical hash over all critical envelope fields.
///
/// A domain separator ([`DOMAIN_SEPARATOR`]) is prepended to prevent
/// cross-protocol signature confusion when the same Ed25519 key is reused
/// across different signing contexts.
///
/// Variable-length fields (`context_id`, `sender_did`) are prefixed with
/// their length as a 4-byte big-endian u32 to prevent field-boundary
/// ambiguity. `payload_hash` and `provenance_hash` are typed as `&[u8; 32]`
/// (SHA-256 outputs) and are also length-prefixed for defense in depth.
/// Fixed-width u64 fields (`epoch`, `generation`, `sequence`, `timestamp`)
/// need no length prefix. The `message_type` discriminator byte is included
/// to prevent type-flipping attacks (issue #290).
///
/// ```text
/// SHA-256(DOMAIN_SEPARATOR || version_BE
///         || message_type_byte
///         || len(context_id) || context_id
///         || len(sender_did) || sender_did || epoch_BE
///         || generation_BE || sequence_BE || timestamp_BE
///         || len(payload_hash) || payload_hash
///         || len(provenance_hash) || provenance_hash
///         || len(signing_key_id) || signing_key_id)
/// ```
pub(crate) fn compute_canonical_hash(
    params: &InnerEnvelopeParams<'_>,
    payload_hash: &[u8; 32],
    provenance_hash: &[u8; 32],
) -> Vec<u8> {
    use crate::crypto::canonical::{CanonicalField, canonical_hash};

    // Field order per §13.2.1: version, message_type (discriminator byte),
    // context_id, sender_did, epoch, generation, sequence, timestamp,
    // payload_hash, provenance_hash, signing_key_id.
    //
    // version from params is field 1 per §13.2.1 — part of the signature
    // commitment. message_type follows as a discriminator byte to prevent
    // type-flipping attacks (issue #290).
    canonical_hash(
        "SCP-INNER-ENVELOPE-V1:",
        &[
            CanonicalField::U16(params.version),
            CanonicalField::U8(params.message_type.as_discriminator_byte()),
            CanonicalField::VarBytes(params.context_id.as_bytes()),
            CanonicalField::VarBytes(params.sender_did.as_bytes()),
            CanonicalField::U64(params.epoch),
            CanonicalField::U64(params.generation),
            CanonicalField::U64(params.sequence),
            CanonicalField::U64(params.timestamp),
            CanonicalField::VarBytes(payload_hash),
            CanonicalField::VarBytes(provenance_hash),
            CanonicalField::VarBytes(params.signing_key_id.as_bytes()),
        ],
    )
    .to_vec()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::match_same_arms
)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn domain_separator_changes_canonical_hash() {
        let payload_hash: [u8; 32] = Sha256::digest(b"test").into();
        let provenance_hash: [u8; 32] = Sha256::digest([0x00]).into();

        // Hash with the real domain separator (via the production function).
        let params = InnerEnvelopeParams {
            version: SCP_INNER_ENVELOPE_VERSION,
            context_id: "ctx-1",
            sender_did: "did:dht:alice",
            epoch: 1,
            generation: 0,
            sequence: 1,
            timestamp: 1_700_000_000,
            message_type: MessageType::Content,
            payload: b"test",
            provenance: None,
            signing_key_id: SigningKeyId::Active,
        };
        let hash_with_domain = compute_canonical_hash(&params, &payload_hash, &provenance_hash);

        // Hash WITHOUT any domain separator (manual construction with length prefixes).
        #[allow(clippy::cast_possible_truncation)]
        let hash_without_domain = {
            let mut h = Sha256::new();
            // No domain separator
            h.update((5u32).to_be_bytes());
            h.update(b"ctx-1");
            h.update((13u32).to_be_bytes());
            h.update(b"did:dht:alice");
            h.update(1u64.to_be_bytes());
            h.update(0u64.to_be_bytes());
            h.update(1u64.to_be_bytes());
            h.update(1_700_000_000u64.to_be_bytes());
            h.update(payload_hash);
            h.update(provenance_hash);
            h.finalize().to_vec()
        };

        // Hash with a DIFFERENT domain separator (manual construction with length prefixes).
        #[allow(clippy::cast_possible_truncation)]
        let hash_alt_domain = {
            let mut h = Sha256::new();
            h.update(b"DIFFERENT-DOMAIN:");
            h.update((5u32).to_be_bytes());
            h.update(b"ctx-1");
            h.update((13u32).to_be_bytes());
            h.update(b"did:dht:alice");
            h.update(1u64.to_be_bytes());
            h.update(0u64.to_be_bytes());
            h.update(1u64.to_be_bytes());
            h.update(1_700_000_000u64.to_be_bytes());
            h.update(payload_hash);
            h.update(provenance_hash);
            h.finalize().to_vec()
        };

        assert_ne!(
            hash_with_domain, hash_without_domain,
            "domain separator must change hash vs. no separator"
        );
        assert_ne!(
            hash_with_domain, hash_alt_domain,
            "different domain separator must produce different hash"
        );
    }

    /// #863: `from_bytes` rejects input exceeding `MAX_ENVELOPE_SIZE` before
    /// invoking the deserializer (parity with `OuterEnvelope::from_bytes`).
    #[test]
    fn from_bytes_rejects_oversized_input() {
        use crate::serde_util::MAX_ENVELOPE_SIZE;

        let oversized = vec![0u8; MAX_ENVELOPE_SIZE + 1];
        let result = InnerEnvelope::from_bytes(&oversized);
        assert!(result.is_err());

        let err_msg = format!("{result:?}");
        assert!(
            err_msg.contains("EnvelopeTooLarge"),
            "error should be EnvelopeTooLarge, got: {err_msg}"
        );
    }

    /// #863: `from_bytes` accepts input at exactly `MAX_ENVELOPE_SIZE` (the
    /// size check is not off-by-one). The deserialization itself will fail
    /// because the bytes are not valid `MessagePack`, but the size check passes.
    #[test]
    fn from_bytes_accepts_at_limit() {
        use crate::serde_util::MAX_ENVELOPE_SIZE;

        let at_limit = vec![0u8; MAX_ENVELOPE_SIZE];
        let result = InnerEnvelope::from_bytes(&at_limit);
        // Should fail with DeserializationFailed (invalid msgpack), not
        // EnvelopeTooLarge.
        assert!(result.is_err());
        let err_msg = format!("{result:?}");
        assert!(
            err_msg.contains("DeserializationFailed"),
            "should be DeserializationFailed at the limit, got: {err_msg}"
        );
    }

    #[test]
    fn provenance_hash_absent_uses_sentinel() {
        // Verify that SHA-256(0x00) is used for absent provenance.
        let expected: [u8; 32] = Sha256::digest([0x00]).into();
        let hash = compute_provenance_hash(None).unwrap();
        assert_eq!(hash, expected);
    }
}
