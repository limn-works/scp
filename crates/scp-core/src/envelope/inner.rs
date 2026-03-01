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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use scp_platform::traits::{KeyCustody, KeyHandle};

use super::EnvelopeError;
use super::padding::pad_to_bucket;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Discriminator for the type of payload carried by an inner envelope.
///
/// Distinguishes regular content messages from protocol-level signaling
/// messages (e.g., WebRTC SDP offers/answers and ICE candidates). The
/// discriminator is included in the canonical hash to prevent type-flipping
/// attacks where an attacker reinterprets a content message as signaling or
/// vice versa.
///
/// See ADR-024 acceptance criteria 5 in `.docs/adrs/phase-5.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum MessageType {
    /// Regular content message (chat, tool output, etc.).
    #[default]
    Content,

    /// WebRTC signaling message (SDP offer/answer, ICE candidate).
    Signaling,
}

impl MessageType {
    /// Returns a single-byte discriminator for inclusion in canonical hashes.
    ///
    /// Using a fixed-width encoding prevents ambiguity in the hash input.
    #[must_use]
    pub fn as_discriminator_byte(&self) -> u8 {
        match self {
            Self::Content => 0,
            Self::Signaling => 1,
        }
    }
}

/// Provenance metadata attached to an inner envelope.
///
/// Provenance tracks the origin of message content — which tool generated it,
/// which agent produced it, and any upstream references. The exact structure
/// will be expanded in later phases; this provides a serializable placeholder.
///
/// See spec section 7.7 for the full provenance model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Human-readable description of the content origin.
    pub source: String,
    /// Optional upstream content hash for chain-of-custody tracking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_hash: Option<String>,
}

/// The inner envelope — the authenticated, encrypted payload visible only to
/// MLS group members after decryption.
///
/// All fields are serialized with `MessagePack` via `rmp-serde`. Binary fields
/// use `serde_bytes` for efficient `MessagePack` binary encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnerEnvelope {
    /// The SCP context identifier.
    pub context_id: String,

    /// The sender's full DID.
    pub sender_did: String,

    /// MLS epoch number.
    pub epoch: u64,

    /// MLS generation number.
    pub generation: u64,

    /// SCP per-sender monotonic sequence number.
    pub sequence: u64,

    /// Creation timestamp (Unix milliseconds).
    pub timestamp: u64,

    /// Discriminator for the payload type.
    ///
    /// Defaults to [`MessageType::Content`] for backward compatibility with
    /// envelopes created before this field was introduced. The discriminator
    /// is included in the canonical hash to prevent type-flipping attacks.
    #[serde(default)]
    pub message_type: MessageType,

    /// SHA-256 hash of the original plaintext payload (before padding).
    #[serde(with = "serde_bytes")]
    pub payload_hash: Vec<u8>,

    /// The message payload (after bucket padding).
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,

    /// Optional provenance metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,

    /// SHA-256 hash of the serialized provenance (or SHA-256(0x00) if absent).
    #[serde(with = "serde_bytes")]
    pub provenance_hash: Vec<u8>,

    /// Ed25519 signature over the canonical hash of all critical fields.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/// Creates an inner envelope with a signed, padded payload.
///
/// The message type defaults to [`MessageType::Content`]. Use
/// [`create_inner_envelope_typed`] to specify a different message type
/// (e.g., [`MessageType::Signaling`] for WebRTC signaling messages).
///
/// **Processing order:**
/// 1. Compute `payload_hash = SHA-256(payload)` (original plaintext).
/// 2. Compute `provenance_hash = SHA-256(serialize(provenance))` if present,
///    or `SHA-256(0x00)` if absent.
/// 3. Compute the canonical hash over all critical fields (including
///    `message_type`).
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
#[allow(clippy::too_many_arguments)]
pub async fn create_inner_envelope(
    context_id: &str,
    sender_did: &str,
    epoch: u64,
    generation: u64,
    sequence: u64,
    timestamp: u64,
    payload: &[u8],
    provenance: Option<Provenance>,
    key_custody: &impl KeyCustody,
    signing_key: &KeyHandle,
) -> Result<InnerEnvelope, EnvelopeError> {
    create_inner_envelope_typed(
        context_id,
        sender_did,
        epoch,
        generation,
        sequence,
        timestamp,
        MessageType::Content,
        payload,
        provenance,
        key_custody,
        signing_key,
    )
    .await
}

/// Creates an inner envelope with an explicit [`MessageType`].
///
/// Identical to [`create_inner_envelope`] but accepts a `message_type`
/// parameter. The message type is included in the canonical hash, so
/// changing it after signing invalidates the signature. This prevents
/// type-flipping attacks (e.g., reinterpreting a content message as
/// signaling or vice versa).
///
/// # Errors
///
/// Returns [`EnvelopeError::SigningFailed`] if the signing operation fails.
/// Returns [`EnvelopeError::SerializationFailed`] if provenance serialization fails.
/// Returns [`EnvelopeError::PayloadTooLarge`] if the payload exceeds the
/// maximum bucket size.
#[allow(clippy::too_many_arguments)]
pub async fn create_inner_envelope_typed(
    context_id: &str,
    sender_did: &str,
    epoch: u64,
    generation: u64,
    sequence: u64,
    timestamp: u64,
    message_type: MessageType,
    payload: &[u8],
    provenance: Option<Provenance>,
    key_custody: &impl KeyCustody,
    signing_key: &KeyHandle,
) -> Result<InnerEnvelope, EnvelopeError> {
    // 1. Hash original plaintext.
    let payload_hash = Sha256::digest(payload).to_vec();

    // 2. Hash provenance.
    let provenance_hash = compute_provenance_hash(provenance.as_ref())?;

    // 3. Compute canonical hash for signing.
    let canonical_hash = compute_canonical_hash(
        context_id,
        sender_did,
        epoch,
        generation,
        sequence,
        timestamp,
        message_type,
        &payload_hash,
        &provenance_hash,
    );

    // 4. Sign the canonical hash.
    let signature = key_custody
        .sign(signing_key, &canonical_hash)
        .await
        .map_err(|e| EnvelopeError::SigningFailed(e.to_string()))?;

    // 5. Pad payload to bucket boundary.
    let padded_payload = pad_to_bucket(payload)?;

    // 6. Build and return the envelope.
    Ok(InnerEnvelope {
        context_id: context_id.to_owned(),
        sender_did: sender_did.to_owned(),
        epoch,
        generation,
        sequence,
        timestamp,
        message_type,
        payload_hash,
        payload: padded_payload,
        provenance,
        provenance_hash,
        signature: signature.into_bytes(),
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
/// # Errors
///
/// Returns [`EnvelopeError::VerificationFailed`] if the public key or
/// signature bytes are malformed. Returns `Ok(false)` if the signature is
/// well-formed but does not match.
pub fn verify_inner_signature(
    inner: &InnerEnvelope,
    sender_public_key: &[u8],
) -> Result<bool, EnvelopeError> {
    // Parse the public key.
    let pubkey_bytes: [u8; 32] = sender_public_key.try_into().map_err(|_| {
        EnvelopeError::VerificationFailed(format!(
            "public key must be 32 bytes, got {}",
            sender_public_key.len()
        ))
    })?;

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| EnvelopeError::VerificationFailed(e.to_string()))?;

    // Parse the signature.
    let sig_bytes: [u8; 64] = inner.signature.as_slice().try_into().map_err(|_| {
        EnvelopeError::VerificationFailed(format!(
            "signature must be 64 bytes, got {}",
            inner.signature.len()
        ))
    })?;

    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    // Recompute the provenance hash from the stored provenance.
    let provenance_hash = compute_provenance_hash(inner.provenance.as_ref())
        .map_err(|e| EnvelopeError::VerificationFailed(e.to_string()))?;

    // Recompute the canonical hash.
    let canonical_hash = compute_canonical_hash(
        &inner.context_id,
        &inner.sender_did,
        inner.epoch,
        inner.generation,
        inner.sequence,
        inner.timestamp,
        inner.message_type,
        &inner.payload_hash,
        &provenance_hash,
    );

    // Verify.
    match verifying_key.verify_strict(&canonical_hash, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Domain separator prepended to the canonical hash input to prevent
/// cross-protocol signature confusion. Because the same Ed25519 key may be
/// used for multiple signing purposes (envelope, UCAN, DID auth), a unique
/// prefix ensures that a signature produced for one context can never be
/// replayed as valid in another.
const DOMAIN_SEPARATOR: &[u8] = b"SCP-INNER-ENVELOPE-V1:";

/// Computes `SHA-256(serialize(provenance))` if present, or `SHA-256(0x00)` if
/// absent.
fn compute_provenance_hash(provenance: Option<&Provenance>) -> Result<Vec<u8>, EnvelopeError> {
    match provenance {
        Some(p) => {
            let serialized = rmp_serde::to_vec(p)
                .map_err(|e| EnvelopeError::SerializationFailed(e.to_string()))?;
            Ok(Sha256::digest(&serialized).to_vec())
        }
        None => Ok(Sha256::digest([0x00]).to_vec()),
    }
}

/// Computes the canonical hash over all critical envelope fields.
///
/// A domain separator ([`DOMAIN_SEPARATOR`]) is prepended to prevent
/// cross-protocol signature confusion when the same Ed25519 key is reused
/// across different signing contexts.
///
/// The `message_type` discriminator byte is included after the timestamp to
/// prevent type-flipping attacks. This ensures a signature over a content
/// message cannot be replayed as a signaling message (or vice versa).
///
/// ```text
/// SHA-256(DOMAIN_SEPARATOR || context_id || sender_did || epoch_BE
///         || generation_BE || sequence_BE || timestamp_BE
///         || message_type_byte || payload_hash || provenance_hash)
/// ```
#[allow(clippy::too_many_arguments)]
fn compute_canonical_hash(
    context_id: &str,
    sender_did: &str,
    epoch: u64,
    generation: u64,
    sequence: u64,
    timestamp: u64,
    message_type: MessageType,
    payload_hash: &[u8],
    provenance_hash: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEPARATOR);
    hasher.update(context_id.as_bytes());
    hasher.update(sender_did.as_bytes());
    hasher.update(epoch.to_be_bytes());
    hasher.update(generation.to_be_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update([message_type.as_discriminator_byte()]);
    hasher.update(payload_hash);
    hasher.update(provenance_hash);
    hasher.finalize().to_vec()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
            "ctx-1",
            "did:dht:alice",
            1,
            0,
            1,
            1_700_000_000,
            b"hello world",
            None,
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        // Verify the signature.
        let valid = verify_inner_signature(&envelope, pubkey.as_bytes()).unwrap();
        assert!(valid, "signature should be valid");

        // Verify payload_hash matches original payload.
        let expected_hash = Sha256::digest(b"hello world").to_vec();
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
            "ctx-2",
            "did:dht:bob",
            5,
            3,
            10,
            1_700_000_000,
            b"payload with provenance",
            Some(provenance.clone()),
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
            "ctx-1",
            "did:dht:alice",
            1,
            0,
            1,
            1_700_000_000,
            b"hello",
            None,
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
            "ctx-1",
            "did:dht:alice",
            1,
            0,
            1,
            1_700_000_000,
            b"original",
            None,
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        // Tamper with the payload hash.
        envelope.payload_hash = vec![0xFF; 32];

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
            "ctx-1",
            "did:dht:alice",
            1,
            0,
            1,
            1_700_000_000,
            b"data",
            Some(provenance),
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
            "ctx-1",
            "did:dht:alice",
            1,
            0,
            1,
            1_700_000_000,
            b"data",
            None,
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
        let expected = Sha256::digest([0x00]).to_vec();
        let hash = compute_provenance_hash(None).unwrap();
        assert_eq!(hash, expected);
    }

    #[tokio::test]
    async fn inner_envelope_serializes_with_msgpack() {
        let (custody, signing_key) = setup().await;

        let envelope = create_inner_envelope(
            "ctx-1",
            "did:dht:alice",
            1,
            0,
            1,
            1_700_000_000,
            b"msgpack test",
            None,
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
        assert_eq!(envelope.signature, deserialized.signature);
    }

    #[tokio::test]
    async fn verify_invalid_pubkey_length_returns_error() {
        let (custody, signing_key) = setup().await;

        let envelope = create_inner_envelope(
            "ctx-1",
            "did:dht:alice",
            1,
            0,
            1,
            1_700_000_000,
            b"test",
            None,
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
        let payload_hash = Sha256::digest(b"test").to_vec();
        let provenance_hash = Sha256::digest([0x00]).to_vec();

        // Hash with the real domain separator (via the production function).
        let hash_with_domain = compute_canonical_hash(
            "ctx-1",
            "did:dht:alice",
            1,
            0,
            1,
            1_700_000_000,
            MessageType::Content,
            &payload_hash,
            &provenance_hash,
        );

        // Hash WITHOUT any domain separator (manual construction).
        let hash_without_domain = {
            let mut h = Sha256::new();
            h.update(b"ctx-1");
            h.update(b"did:dht:alice");
            h.update(1u64.to_be_bytes());
            h.update(0u64.to_be_bytes());
            h.update(1u64.to_be_bytes());
            h.update(1_700_000_000u64.to_be_bytes());
            h.update([0u8]);
            h.update(&payload_hash);
            h.update(&provenance_hash);
            h.finalize().to_vec()
        };

        // Hash with a DIFFERENT domain separator (manual construction).
        let hash_alt_domain = {
            let mut h = Sha256::new();
            h.update(b"DIFFERENT-DOMAIN:");
            h.update(b"ctx-1");
            h.update(b"did:dht:alice");
            h.update(1u64.to_be_bytes());
            h.update(0u64.to_be_bytes());
            h.update(1u64.to_be_bytes());
            h.update(1_700_000_000u64.to_be_bytes());
            h.update([0u8]);
            h.update(&payload_hash);
            h.update(&provenance_hash);
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

    #[test]
    fn message_type_changes_canonical_hash() {
        let payload_hash = Sha256::digest(b"test").to_vec();
        let provenance_hash = Sha256::digest([0x00]).to_vec();

        let hash_content = compute_canonical_hash(
            "ctx-1",
            "did:dht:alice",
            1,
            0,
            1,
            1_700_000_000,
            MessageType::Content,
            &payload_hash,
            &provenance_hash,
        );

        let hash_signaling = compute_canonical_hash(
            "ctx-1",
            "did:dht:alice",
            1,
            0,
            1,
            1_700_000_000,
            MessageType::Signaling,
            &payload_hash,
            &provenance_hash,
        );

        assert_ne!(
            hash_content, hash_signaling,
            "different message types must produce different canonical hashes"
        );
    }

    #[tokio::test]
    async fn create_typed_envelope_with_signaling() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let envelope = create_inner_envelope_typed(
            "ctx-1",
            "did:dht:alice",
            1,
            0,
            1,
            1_700_000_000,
            MessageType::Signaling,
            b"signaling payload",
            None,
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        assert_eq!(envelope.message_type, MessageType::Signaling);

        let valid = verify_inner_signature(&envelope, pubkey.as_bytes()).unwrap();
        assert!(valid, "signaling envelope signature should verify");
    }

    #[tokio::test]
    async fn signaling_signature_rejects_type_flip_to_content() {
        let (custody, signing_key) = setup().await;
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let mut envelope = create_inner_envelope_typed(
            "ctx-1",
            "did:dht:alice",
            1,
            0,
            1,
            1_700_000_000,
            MessageType::Signaling,
            b"payload",
            None,
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        envelope.message_type = MessageType::Content;

        let valid = verify_inner_signature(&envelope, pubkey.as_bytes()).unwrap();
        assert!(!valid, "type-flipped envelope must fail verification");
    }

    #[tokio::test]
    async fn default_create_uses_content_type() {
        let (custody, signing_key) = setup().await;

        let envelope = create_inner_envelope(
            "ctx-1",
            "did:dht:alice",
            1,
            0,
            1,
            1_700_000_000,
            b"hello",
            None,
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        assert_eq!(envelope.message_type, MessageType::Content);
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
                        "ctx-prop",
                        "did:dht:proptest",
                        1,
                        0,
                        1,
                        1_700_000_000,
                        &payload,
                        None,
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
    }
}
