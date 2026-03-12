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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use scp_platform::traits::{KeyCustody, KeyHandle};

use super::EnvelopeError;
use super::padding::pad_to_bucket;
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
// Construction
// ---------------------------------------------------------------------------

/// Creates an inner envelope with a signed, padded payload.
///
/// **Processing order:**
/// 1. Compute `payload_hash = SHA-256(payload)` (original plaintext).
/// 2. Compute `provenance_hash = SHA-256(serialize(provenance))` if present,
///    or `SHA-256(0x00)` if absent.
/// 3. Compute the canonical hash over all critical fields.
/// 4. Sign the canonical hash with `key_custody.sign(signing_key, hash)`.
/// 5. Pad the payload to the next bucket boundary.
/// 6. Return the complete inner envelope.
///
/// # Errors
///
/// Returns [`EnvelopeError::SigningFailed`] if the signing operation fails.
/// Returns [`EnvelopeError::SerializationFailed`] if provenance serialization fails.
/// Returns [`EnvelopeError::PayloadTooLarge`] if the payload exceeds the
/// maximum bucket size.
pub async fn create_inner_envelope(
    params: &InnerEnvelopeParams<'_>,
    key_custody: &impl KeyCustody,
    signing_key: &KeyHandle,
) -> Result<InnerEnvelope, EnvelopeError> {
    // 1. Hash original plaintext.
    let payload_hash: [u8; 32] = Sha256::digest(params.payload).into();

    // 2. Hash provenance.
    let provenance_hash: [u8; 32] = compute_provenance_hash(params.provenance.as_ref())?;

    // 3. Compute canonical hash for signing.
    let canonical_hash = compute_canonical_hash(params, &payload_hash, &provenance_hash);

    // 4. Sign the canonical hash.
    let signature = key_custody
        .sign(signing_key, &canonical_hash)
        .await
        .map_err(|e| EnvelopeError::SigningFailed(e.to_string()))?;

    // 5. Pad payload to bucket boundary.
    let padded_payload = pad_to_bucket(params.payload)?;

    // 6. Build and return the envelope.
    let sig_bytes: [u8; 64] = signature
        .into_bytes()
        .try_into()
        .map_err(|_| EnvelopeError::SigningFailed("Ed25519 signature must be 64 bytes".into()))?;

    Ok(InnerEnvelope {
        version: SCP_INNER_ENVELOPE_VERSION,
        context_id: params.context_id.to_owned(),
        sender_did: params.sender_did.to_owned(),
        epoch: params.epoch,
        generation: params.generation,
        sequence: params.sequence,
        timestamp: params.timestamp,
        message_type: params.message_type,
        payload_hash,
        payload: padded_payload,
        provenance: params.provenance.clone(),
        provenance_hash,
        signing_key_id: params.signing_key_id,
        signature: sig_bytes,
        extensions: HashMap::new(),
    })
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

    // Reject unsupported protocol versions before signature verification.
    if inner.version != SCP_INNER_ENVELOPE_VERSION {
        return Err(EnvelopeError::UnsupportedVersion {
            version: inner.version,
        });
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
            // Signature mismatch → Ok(false). Malformed inputs → Err.
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

/// Validates that an inner envelope's version field is supported (§13.2.1).
///
/// Currently only SCP/1.0 (`0x0100`) is recognized. Call this after
/// deserialization to reject envelopes from incompatible protocol versions.
///
/// # Errors
///
/// Returns [`EnvelopeError::UnsupportedVersion`] if `inner.version` is not
/// `SCP_INNER_ENVELOPE_VERSION`.
pub const fn validate_inner_version(inner: &InnerEnvelope) -> Result<(), EnvelopeError> {
    if inner.version != SCP_INNER_ENVELOPE_VERSION {
        return Err(EnvelopeError::UnsupportedVersion {
            version: inner.version,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Domain separator prepended to the canonical hash input to prevent
/// cross-protocol signature confusion. Because the same Ed25519 key may be
/// Computes `SHA-256(serialize(provenance))` if present, or `SHA-256(0x00)` if
/// absent. Returns a fixed-size 32-byte array (SHA-256 output).
fn compute_provenance_hash(provenance: Option<&Provenance>) -> Result<[u8; 32], EnvelopeError> {
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
fn compute_canonical_hash(
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
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::KeyType;

    use super::*;
    use crate::envelope::padding::strip_padding;

    async fn setup() -> (InMemoryKeyCustody, KeyHandle) {
        let custody = InMemoryKeyCustody::new();
        let key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        (custody, key)
    }

    #[tokio::test]
    async fn create_and_verify_inner_envelope_no_provenance() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"hello world",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        // Verify the signature.
        let valid = verify_inner_signature(&envelope, pubkey.as_bytes()).unwrap();
        assert!(valid, "signature should be valid");

        // Verify signing_key_id is preserved.
        assert_eq!(envelope.signing_key_id, SigningKeyId::Active);

        // Verify payload_hash matches original payload.
        let expected_hash: [u8; 32] = Sha256::digest(b"hello world").into();
        assert_eq!(envelope.payload_hash, expected_hash);

        // Verify payload is padded.
        assert_eq!(envelope.payload.len(), 256);

        // Verify we can strip padding to recover original.
        let recovered = strip_padding(&envelope.payload).unwrap();
        assert_eq!(recovered, b"hello world");
    }

    #[tokio::test]
    async fn create_and_verify_inner_envelope_with_provenance() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let provenance = Provenance {
            source: "test-tool".into(),
            upstream_hash: Some("abc123".into()),
        };

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-2",
                sender_did: "did:dht:bob",
                epoch: 5,
                generation: 3,
                sequence: 10,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"payload with provenance",
                provenance: Some(provenance.clone()),
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        let valid = verify_inner_signature(&envelope, pubkey.as_bytes()).unwrap();
        assert!(valid, "signature should be valid with provenance");

        // Verify provenance is preserved.
        assert_eq!(envelope.provenance, Some(provenance));
    }

    #[tokio::test]
    async fn verify_rejects_wrong_public_key() {
        let (custody, signing_key) = setup().await;
        let other_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let wrong_pubkey = custody.public_key(&other_key).await.unwrap();

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"hello",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        let valid = verify_inner_signature(&envelope, wrong_pubkey.as_bytes()).unwrap();
        assert!(!valid, "signature should be invalid with wrong key");
    }

    #[tokio::test]
    async fn verify_rejects_tampered_payload_hash() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let mut envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"original",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        // Tamper with the payload hash.
        envelope.payload_hash = [0xFF; 32];

        let valid = verify_inner_signature(&envelope, pubkey.as_bytes()).unwrap();
        assert!(!valid, "tampered payload hash should invalidate signature");
    }

    #[tokio::test]
    async fn verify_rejects_tampered_provenance() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let provenance = Provenance {
            source: "original-tool".into(),
            upstream_hash: None,
        };

        let mut envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"data",
                provenance: Some(provenance),
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        // Strip provenance — should invalidate the signature.
        envelope.provenance = None;

        let valid = verify_inner_signature(&envelope, pubkey.as_bytes()).unwrap();
        assert!(!valid, "stripping provenance should invalidate signature");
    }

    #[tokio::test]
    async fn verify_rejects_added_provenance() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"data",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        // Add provenance to an envelope that had none — should invalidate.
        let mut tampered = envelope;
        tampered.provenance = Some(Provenance {
            source: "injected".into(),
            upstream_hash: None,
        });

        let valid = verify_inner_signature(&tampered, pubkey.as_bytes()).unwrap();
        assert!(!valid, "adding provenance should invalidate signature");
    }

    #[tokio::test]
    async fn provenance_hash_absent_uses_sentinel() {
        // Verify that SHA-256(0x00) is used for absent provenance.
        let expected: [u8; 32] = Sha256::digest([0x00]).into();
        let hash = compute_provenance_hash(None).unwrap();
        assert_eq!(hash, expected);
    }

    #[tokio::test]
    async fn inner_envelope_serializes_with_msgpack() {
        let (custody, signing_key) = setup().await;

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"msgpack test",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        let bytes = rmp_serde::to_vec_named(&envelope).unwrap();
        let deserialized: InnerEnvelope = rmp_serde::from_slice(&bytes).unwrap();

        assert_eq!(envelope.context_id, deserialized.context_id);
        assert_eq!(envelope.sender_did, deserialized.sender_did);
        assert_eq!(envelope.epoch, deserialized.epoch);
        assert_eq!(envelope.payload_hash, deserialized.payload_hash);
        assert_eq!(envelope.signing_key_id, deserialized.signing_key_id);
        assert_eq!(envelope.signature, deserialized.signature);
    }

    #[tokio::test]
    async fn verify_invalid_pubkey_length_returns_error() {
        let (custody, signing_key) = setup().await;

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
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
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        let result = verify_inner_signature(&envelope, &[0u8; 16]);
        assert!(result.is_err());
    }

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

    // -------------------------------------------------------------------
    // MessageType tests (issue #290)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn verify_rejects_tampered_message_type() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let mut envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"content message",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        // Tamper: flip message_type from Content to Signaling.
        envelope.message_type = MessageType::Signaling;

        let valid = verify_inner_signature(&envelope, pubkey.as_bytes()).unwrap();
        assert!(
            !valid,
            "changing message_type after signing must invalidate signature"
        );
    }

    #[tokio::test]
    async fn create_and_verify_signaling_envelope() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Signaling,
                payload: b"signaling payload",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        assert_eq!(envelope.message_type, MessageType::Signaling);
        let valid = verify_inner_signature(&envelope, pubkey.as_bytes()).unwrap();
        assert!(valid, "Signaling envelope should verify");
    }

    #[tokio::test]
    async fn different_message_types_produce_different_signatures() {
        let (custody, signing_key) = setup().await;

        let content_envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"same payload",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        let signaling_envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Signaling,
                payload: b"same payload",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        assert_ne!(
            content_envelope.signature, signaling_envelope.signature,
            "different message_type must produce different signatures"
        );
    }

    #[tokio::test]
    async fn message_type_msgpack_roundtrip() {
        let (custody, signing_key) = setup().await;

        for msg_type in [MessageType::Content, MessageType::Signaling] {
            let envelope = create_inner_envelope(
                &InnerEnvelopeParams {
                    version: SCP_INNER_ENVELOPE_VERSION,
                    context_id: "ctx-1",
                    sender_did: "did:dht:alice",
                    epoch: 1,
                    generation: 0,
                    sequence: 1,
                    timestamp: 1_700_000_000,
                    message_type: msg_type,
                    payload: b"roundtrip test",
                    provenance: None,
                    signing_key_id: SigningKeyId::Active,
                },
                &custody,
                &signing_key,
            )
            .await
            .unwrap();

            let bytes = rmp_serde::to_vec_named(&envelope).unwrap();
            let deserialized: InnerEnvelope = rmp_serde::from_slice(&bytes).unwrap();
            assert_eq!(deserialized.message_type, msg_type);
        }
    }

    // -------------------------------------------------------------------
    // SigningKeyId-specific tests (ADR-039)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn create_and_verify_inner_envelope_with_active_signing_key() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"active key message",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        assert_eq!(envelope.signing_key_id, SigningKeyId::Active);
        let valid = verify_inner_signature(&envelope, pubkey.as_bytes()).unwrap();
        assert!(valid, "Active signing key envelope should verify");
    }

    #[tokio::test]
    async fn create_and_verify_inner_envelope_with_agent_signing_key() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"agent key message",
                provenance: None,
                signing_key_id: SigningKeyId::Agent,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        assert_eq!(envelope.signing_key_id, SigningKeyId::Agent);
        let valid = verify_inner_signature(&envelope, pubkey.as_bytes()).unwrap();
        assert!(valid, "Agent signing key envelope should verify");
    }

    #[tokio::test]
    async fn verify_rejects_tampered_signing_key_id() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let mut envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"signed as active",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        // Tamper: flip signing_key_id from Active to Agent.
        envelope.signing_key_id = SigningKeyId::Agent;

        let valid = verify_inner_signature(&envelope, pubkey.as_bytes()).unwrap();
        assert!(
            !valid,
            "tampering with signing_key_id must invalidate signature"
        );
    }

    #[tokio::test]
    async fn different_signing_key_ids_produce_different_signatures() {
        let (custody, signing_key) = setup().await;

        let active_envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"same payload",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        let agent_envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"same payload",
                provenance: None,
                signing_key_id: SigningKeyId::Agent,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        assert_ne!(
            active_envelope.signature, agent_envelope.signature,
            "different signing_key_id must produce different signatures"
        );
    }

    #[tokio::test]
    async fn inner_envelope_serde_defaults_signing_key_id_to_active() {
        // Simulate an old-format envelope by serializing without signing_key_id
        // then deserializing — serde(default) should give Active.
        let (custody, signing_key) = setup().await;

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"compat test",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        // Serialize to JSON, remove signing_key_id, deserialize back.
        let mut json_val: serde_json::Value = serde_json::to_value(&envelope).unwrap();
        json_val.as_object_mut().unwrap().remove("signing_key_id");
        let deserialized: InnerEnvelope = serde_json::from_value(json_val).unwrap();

        assert_eq!(
            deserialized.signing_key_id,
            SigningKeyId::Active,
            "missing signing_key_id should default to Active"
        );
    }

    #[tokio::test]
    async fn signing_key_id_msgpack_roundtrip() {
        let (custody, signing_key) = setup().await;

        for key_id in [SigningKeyId::Active, SigningKeyId::Agent] {
            let envelope = create_inner_envelope(
                &InnerEnvelopeParams {
                    version: SCP_INNER_ENVELOPE_VERSION,
                    context_id: "ctx-1",
                    sender_did: "did:dht:alice",
                    epoch: 1,
                    generation: 0,
                    sequence: 1,
                    timestamp: 1_700_000_000,
                    message_type: MessageType::Content,
                    payload: b"msgpack roundtrip",
                    provenance: None,
                    signing_key_id: key_id,
                },
                &custody,
                &signing_key,
            )
            .await
            .unwrap();

            let bytes = rmp_serde::to_vec_named(&envelope).unwrap();
            let deserialized: InnerEnvelope = rmp_serde::from_slice(&bytes).unwrap();
            assert_eq!(deserialized.signing_key_id, key_id);
        }
    }

    // -------------------------------------------------------------------
    // Category A enforcement tests (ADR-039, SCP-AB-020)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn enforce_rejects_agent_key_category_a() {
        let (custody, signing_key) = setup().await;

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"modify DID doc",
                provenance: None,
                signing_key_id: SigningKeyId::Agent,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        // Category A action signed by agent key → rejected.
        let result = enforce_inner_envelope_category_a(&envelope, "did_document");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, super::super::EnvelopeError::CategoryAViolation(_)),
            "expected CategoryAViolation, got {err:?}"
        );
    }

    #[tokio::test]
    async fn enforce_accepts_agent_key_category_b() {
        let (custody, signing_key) = setup().await;

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"send message",
                provenance: None,
                signing_key_id: SigningKeyId::Agent,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        // Category B action signed by agent key → accepted.
        let result = enforce_inner_envelope_category_a(&envelope, "messages");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn enforce_accepts_active_key_category_a() {
        let (custody, signing_key) = setup().await;

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"modify DID doc",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        // Category A action signed by active key → accepted.
        let result = enforce_inner_envelope_category_a(&envelope, "did_document");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn enforce_rejects_agent_key_all_category_a_resources() {
        let (custody, signing_key) = setup().await;

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
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
                signing_key_id: SigningKeyId::Agent,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        let category_a_resources = [
            "did_document",
            "verification_method",
            "identity",
            "pre_rotation",
            "service",
            "relay_config",
            "did_migration",
            "key_management",
        ];

        for resource in &category_a_resources {
            let result = enforce_inner_envelope_category_a(&envelope, resource);
            assert!(
                result.is_err(),
                "agent key should be rejected for Category A resource: {resource}"
            );
        }
    }

    mod proptest_inner {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn create_then_verify_roundtrip(payload in proptest::collection::vec(any::<u8>(), 0..4000)) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let (custody, signing_key) = setup().await;
                    let pubkey = custody.public_key(&signing_key).await.unwrap();

                    let envelope = create_inner_envelope(
                        &InnerEnvelopeParams {
                            version: SCP_INNER_ENVELOPE_VERSION,
                            context_id: "ctx-prop",
                            sender_did: "did:dht:proptest",
                            epoch: 1,
                            generation: 0,
                            sequence: 1,
                            timestamp: 1_700_000_000,
                            message_type: MessageType::Content,
                            payload: &payload,
                            provenance: None,
                            signing_key_id: SigningKeyId::Active,
                        },
                        &custody,
                        &signing_key,
                    )
                    .await
                    .unwrap();

                    let valid = verify_inner_signature(&envelope, pubkey.as_bytes()).unwrap();
                    prop_assert!(valid, "roundtrip signature must verify");

                    // Verify payload can be recovered.
                    let recovered = strip_padding(&envelope.payload).unwrap();
                    prop_assert_eq!(recovered, payload);

                    Ok(())
                })?;
            }
        }

        // -------------------------------------------------------------------
        // Version field tests (§13.2.1, #398)
        // -------------------------------------------------------------------

        #[tokio::test]
        async fn inner_envelope_has_version_field() {
            let (custody, signing_key) = setup().await;

            let envelope = create_inner_envelope(
                &InnerEnvelopeParams {
                    version: SCP_INNER_ENVELOPE_VERSION,
                    context_id: "ctx-1",
                    sender_did: "did:dht:alice",
                    epoch: 1,
                    generation: 0,
                    sequence: 1,
                    timestamp: 1_700_000_000,
                    message_type: MessageType::Content,
                    payload: b"version test",
                    provenance: None,
                    signing_key_id: SigningKeyId::Active,
                },
                &custody,
                &signing_key,
            )
            .await
            .unwrap();

            assert_eq!(
                envelope.version, SCP_INNER_ENVELOPE_VERSION,
                "version must match SCP_INNER_ENVELOPE_VERSION"
            );
        }

        #[tokio::test]
        async fn validate_inner_version_accepts_current() {
            let (custody, signing_key) = setup().await;

            let envelope = create_inner_envelope(
                &InnerEnvelopeParams {
                    version: SCP_INNER_ENVELOPE_VERSION,
                    context_id: "ctx-1",
                    sender_did: "did:dht:alice",
                    epoch: 1,
                    generation: 0,
                    sequence: 1,
                    timestamp: 1_700_000_000,
                    message_type: MessageType::Content,
                    payload: b"version ok",
                    provenance: None,
                    signing_key_id: SigningKeyId::Active,
                },
                &custody,
                &signing_key,
            )
            .await
            .unwrap();

            assert!(validate_inner_version(&envelope).is_ok());
        }

        #[tokio::test]
        async fn validate_inner_version_rejects_wrong_version() {
            let (custody, signing_key) = setup().await;

            let mut envelope = create_inner_envelope(
                &InnerEnvelopeParams {
                    version: SCP_INNER_ENVELOPE_VERSION,
                    context_id: "ctx-1",
                    sender_did: "did:dht:alice",
                    epoch: 1,
                    generation: 0,
                    sequence: 1,
                    timestamp: 1_700_000_000,
                    message_type: MessageType::Content,
                    payload: b"wrong version",
                    provenance: None,
                    signing_key_id: SigningKeyId::Active,
                },
                &custody,
                &signing_key,
            )
            .await
            .unwrap();

            // Tamper with version.
            envelope.version = 0x0200;

            let result = validate_inner_version(&envelope);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                format!("{err}").contains("0x0200"),
                "error must include the rejected version"
            );
        }

        #[tokio::test]
        async fn version_is_part_of_signature_commitment() {
            let (custody, signing_key) = setup().await;
            let pubkey = custody.public_key(&signing_key).await.unwrap();

            let mut envelope = create_inner_envelope(
                &InnerEnvelopeParams {
                    version: SCP_INNER_ENVELOPE_VERSION,
                    context_id: "ctx-1",
                    sender_did: "did:dht:alice",
                    epoch: 1,
                    generation: 0,
                    sequence: 1,
                    timestamp: 1_700_000_000,
                    message_type: MessageType::Content,
                    payload: b"version commitment",
                    provenance: None,
                    signing_key_id: SigningKeyId::Active,
                },
                &custody,
                &signing_key,
            )
            .await
            .unwrap();

            // Tamper with version — verification must fail because version is
            // committed in the canonical hash. The verifier rejects unsupported
            // versions before reaching the signature check, so we expect an
            // UnsupportedVersion error (or Ok(false) if version validation
            // were removed — either way, the envelope must not pass).
            envelope.version = 0x0200;

            let result = verify_inner_signature(&envelope, pubkey.as_bytes());
            let rejected = match result {
                Err(_) => true,    // UnsupportedVersion error
                Ok(false) => true, // signature mismatch
                Ok(true) => false, // should not happen
            };
            assert!(
                rejected,
                "changing version after signing must reject the envelope"
            );
        }

        #[tokio::test]
        async fn version_survives_msgpack_roundtrip() {
            let (custody, signing_key) = setup().await;

            let envelope = create_inner_envelope(
                &InnerEnvelopeParams {
                    version: SCP_INNER_ENVELOPE_VERSION,
                    context_id: "ctx-1",
                    sender_did: "did:dht:alice",
                    epoch: 1,
                    generation: 0,
                    sequence: 1,
                    timestamp: 1_700_000_000,
                    message_type: MessageType::Content,
                    payload: b"roundtrip version",
                    provenance: None,
                    signing_key_id: SigningKeyId::Active,
                },
                &custody,
                &signing_key,
            )
            .await
            .unwrap();

            let bytes = rmp_serde::to_vec_named(&envelope).unwrap();
            let deserialized: InnerEnvelope = rmp_serde::from_slice(&bytes).unwrap();
            assert_eq!(deserialized.version, SCP_INNER_ENVELOPE_VERSION);
        }
    }

    // -----------------------------------------------------------------------
    // from_bytes tests (#863)
    // -----------------------------------------------------------------------

    /// #863: Valid envelope serialized to msgpack and deserialized via
    /// `from_bytes` preserves all fields.
    #[tokio::test]
    async fn from_bytes_roundtrip_preserves_fields() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let provenance = Provenance {
            source: "from-bytes-test".into(),
            upstream_hash: Some("upstream-abc".into()),
        };

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-from-bytes",
                sender_did: "did:dht:from-bytes",
                epoch: 7,
                generation: 3,
                sequence: 42,
                timestamp: 1_700_000_000,
                message_type: MessageType::Signaling,
                payload: b"from_bytes roundtrip",
                provenance: Some(provenance.clone()),
                signing_key_id: SigningKeyId::Agent,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        let bytes = rmp_serde::to_vec_named(&envelope).unwrap();
        let decoded = InnerEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.version, SCP_INNER_ENVELOPE_VERSION);
        assert_eq!(decoded.context_id, "ctx-from-bytes");
        assert_eq!(decoded.sender_did, "did:dht:from-bytes");
        assert_eq!(decoded.epoch, 7);
        assert_eq!(decoded.generation, 3);
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.timestamp, 1_700_000_000);
        assert_eq!(decoded.message_type, MessageType::Signaling);
        assert_eq!(decoded.payload_hash, envelope.payload_hash);
        assert_eq!(decoded.payload, envelope.payload);
        assert_eq!(decoded.provenance, Some(provenance));
        assert_eq!(decoded.provenance_hash, envelope.provenance_hash);
        assert_eq!(decoded.signing_key_id, SigningKeyId::Agent);
        assert_eq!(decoded.signature, envelope.signature);

        // Signature must still verify after from_bytes roundtrip.
        let valid = verify_inner_signature(&decoded, pubkey.as_bytes()).unwrap();
        assert!(valid, "signature must verify after from_bytes roundtrip");
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

    // -----------------------------------------------------------------------
    // Forward compatibility: unknown fields preserved (#863, §13.5.1, #593)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn inner_envelope_preserves_unknown_fields_json_roundtrip() {
        let (custody, signing_key) = setup().await;

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-fwd",
                sender_did: "did:dht:fwd-compat",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"forward compat test",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        // Inject an unknown extension field directly and verify msgpack roundtrip.
        let mut envelope_with_ext = envelope;
        envelope_with_ext.extensions.insert(
            "future_protocol_extension".into(),
            rmpv::Value::from("present"),
        );

        let bytes = rmp_serde::to_vec_named(&envelope_with_ext).unwrap();
        let decoded: InnerEnvelope = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded.context_id, "ctx-fwd");
        assert_eq!(decoded.sender_did, "did:dht:fwd-compat");

        // Unknown field must be preserved in extensions.
        assert!(
            decoded.extensions.contains_key("future_protocol_extension"),
            "unknown field must be preserved in extensions, got: {:?}",
            decoded.extensions
        );

        // Re-serialize and re-deserialize — extensions must persist.
        let re_bytes = rmp_serde::to_vec_named(&decoded).unwrap();
        let re_decoded: InnerEnvelope = rmp_serde::from_slice(&re_bytes).unwrap();
        assert!(
            re_decoded
                .extensions
                .contains_key("future_protocol_extension"),
            "extensions must survive msgpack roundtrip"
        );
    }

    /// #863: Extensions must survive a `MessagePack` roundtrip — the actual wire
    /// format. Simulates a newer protocol version adding a field.
    #[test]
    fn inner_envelope_extensions_survive_msgpack_roundtrip() {
        #[derive(serde::Serialize)]
        struct ExtendedInnerEnvelope {
            version: u16,
            #[serde(with = "crate::serde_util::serde_bounded_string")]
            context_id: String,
            #[serde(with = "crate::serde_util::serde_bounded_string")]
            sender_did: String,
            epoch: u64,
            generation: u64,
            sequence: u64,
            timestamp: u64,
            message_type: MessageType,
            #[serde(with = "crate::serde_util::serde_hash_32")]
            payload_hash: [u8; 32],
            #[serde(with = "crate::serde_util::serde_bounded_bytes")]
            payload: Vec<u8>,
            provenance: Option<Provenance>,
            #[serde(with = "crate::serde_util::serde_hash_32")]
            provenance_hash: [u8; 32],
            signing_key_id: SigningKeyId,
            #[serde(with = "crate::serde_util::serde_signature_64")]
            signature: [u8; 64],
            /// Field unknown to the current `InnerEnvelope` definition.
            v2_sender_trust_score: rmpv::Value,
        }

        let trust_map = rmpv::Value::Map(vec![
            (rmpv::Value::from("score"), rmpv::Value::F64(0.95)),
            (rmpv::Value::from("basis"), rmpv::Value::from("direct")),
        ]);

        let extended = ExtendedInnerEnvelope {
            version: SCP_INNER_ENVELOPE_VERSION,
            context_id: "ctx-ext".into(),
            sender_did: "did:dht:ext-test".into(),
            epoch: 1,
            generation: 0,
            sequence: 1,
            timestamp: 1_700_000_000,
            message_type: MessageType::Content,
            payload_hash: Sha256::digest(b"test").into(),
            payload: vec![0xAA; 256],
            provenance: None,
            provenance_hash: Sha256::digest([0x00]).into(),
            signing_key_id: SigningKeyId::Active,
            signature: [0x42; 64],
            v2_sender_trust_score: trust_map,
        };

        // Serialize the extended struct to MessagePack.
        let msgpack_bytes = rmp_serde::to_vec_named(&extended).unwrap();

        // Deserialize as the standard InnerEnvelope.
        let decoded: InnerEnvelope = rmp_serde::from_slice(&msgpack_bytes).unwrap();

        // Known fields must be correct.
        assert_eq!(decoded.context_id, "ctx-ext");
        assert_eq!(decoded.sender_did, "did:dht:ext-test");
        assert_eq!(decoded.epoch, 1);

        // The unknown field must survive in extensions.
        assert!(
            decoded.extensions.contains_key("v2_sender_trust_score"),
            "unknown field must be preserved in extensions after msgpack roundtrip, got: {:?}",
            decoded.extensions
        );
        let ext = &decoded.extensions["v2_sender_trust_score"];
        assert_eq!(ext["score"], rmpv::Value::F64(0.95));
        assert_eq!(ext["basis"], rmpv::Value::from("direct"));

        // Re-serialize and re-deserialize — the extension must persist.
        let re_encoded = rmp_serde::to_vec_named(&decoded).unwrap();
        let re_decoded: InnerEnvelope = rmp_serde::from_slice(&re_encoded).unwrap();
        assert!(
            re_decoded.extensions.contains_key("v2_sender_trust_score"),
            "unknown field must survive msgpack roundtrip"
        );
    }

    /// #863: Extensions must NOT affect canonical hash or signature verification.
    #[tokio::test]
    async fn extensions_excluded_from_signature() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let mut envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                version: SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-ext-sig",
                sender_did: "did:dht:ext-sig-test",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"extensions dont affect sig",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        // Verify original signature.
        let valid = verify_inner_signature(&envelope, pubkey.as_bytes()).unwrap();
        assert!(valid, "original signature must verify");

        // Add extensions — signature must still verify.
        envelope
            .extensions
            .insert("future_field".into(), rmpv::Value::from("future_value"));
        envelope.extensions.insert(
            "another_future_field".into(),
            rmpv::Value::Map(vec![(
                rmpv::Value::from("nested"),
                rmpv::Value::Array(vec![
                    rmpv::Value::from(1),
                    rmpv::Value::from(2),
                    rmpv::Value::from(3),
                ]),
            )]),
        );

        let still_valid = verify_inner_signature(&envelope, pubkey.as_bytes()).unwrap();
        assert!(
            still_valid,
            "extensions must not affect signature verification"
        );
    }
}
