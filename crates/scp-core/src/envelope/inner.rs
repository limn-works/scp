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
}

impl MessageType {
    /// Returns a single-byte discriminator for inclusion in canonical hashes.
    #[must_use]
    pub const fn as_discriminator_byte(&self) -> u8 {
        match self {
            Self::Content => 0,
            Self::Signaling => 1,
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
    /// The message payload (before padding).
    pub payload: &'a [u8],
    /// Optional provenance metadata.
    pub provenance: Option<Provenance>,
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
    let payload_hash = Sha256::digest(params.payload).to_vec();

    // 2. Hash provenance.
    let provenance_hash = compute_provenance_hash(params.provenance.as_ref())?;

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
    Ok(InnerEnvelope {
        context_id: params.context_id.to_owned(),
        sender_did: params.sender_did.to_owned(),
        epoch: params.epoch,
        generation: params.generation,
        sequence: params.sequence,
        timestamp: params.timestamp,
        payload_hash,
        payload: padded_payload,
        provenance: params.provenance.clone(),
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

    // Reconstruct params for canonical hash computation.
    let params = InnerEnvelopeParams {
        context_id: &inner.context_id,
        sender_did: &inner.sender_did,
        epoch: inner.epoch,
        generation: inner.generation,
        sequence: inner.sequence,
        timestamp: inner.timestamp,
        payload: &[],
        provenance: inner.provenance.clone(),
    };

    // Recompute the canonical hash.
    let canonical_hash = compute_canonical_hash(&params, &inner.payload_hash, &provenance_hash);

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
/// across different signing contexts. Variable-length fields (`context_id`,
/// `sender_did`) are prefixed with their length as a 4-byte big-endian u32 to
/// prevent field-boundary ambiguity (e.g., `"abc" || "def"` vs `"abcd" || "ef"`).
///
/// Fixed-width fields (`epoch`, `generation`, `sequence`, `timestamp` as u64 BE;
/// `payload_hash` and `provenance_hash` as 32-byte SHA-256 outputs) need no
/// length prefix.
///
/// ```text
/// SHA-256(DOMAIN_SEPARATOR || len(context_id) || context_id
///         || len(sender_did) || sender_did || epoch_BE
///         || generation_BE || sequence_BE || timestamp_BE
///         || payload_hash || provenance_hash)
/// ```
///
/// Variable-length fields (`context_id`, `sender_did`, `payload_hash`,
/// `provenance_hash`) are length-prefixed with a `u32` big-endian byte count
/// to prevent field-boundary collision attacks (e.g., `context_id="ab"` +
/// `sender_did="cd"` must hash differently from `context_id="abc"` +
/// `sender_did="d"`). Fixed-width fields (`epoch`, `generation`, `sequence`,
/// `timestamp`) need no length prefix.
fn compute_canonical_hash(
    params: &InnerEnvelopeParams<'_>,
    payload_hash: &[u8],
    provenance_hash: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEPARATOR);

    // Length-prefix variable-length fields to prevent boundary ambiguity.
    #[allow(clippy::cast_possible_truncation)]
    let len_prefix = |h: &mut Sha256, data: &[u8]| {
        h.update((data.len() as u32).to_be_bytes());
        h.update(data);
    };
    len_prefix(&mut hasher, params.context_id.as_bytes());
    len_prefix(&mut hasher, params.sender_did.as_bytes());

    // Fixed-width u64 fields -- no length prefix needed.
    hasher.update(params.epoch.to_be_bytes());
    hasher.update(params.generation.to_be_bytes());
    hasher.update(params.sequence.to_be_bytes());
    hasher.update(params.timestamp.to_be_bytes());

    len_prefix(&mut hasher, payload_hash);
    len_prefix(&mut hasher, provenance_hash);
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
            &InnerEnvelopeParams {
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                payload: b"hello world",
                provenance: None,
            },
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
            &InnerEnvelopeParams {
                context_id: "ctx-2",
                sender_did: "did:dht:bob",
                epoch: 5,
                generation: 3,
                sequence: 10,
                timestamp: 1_700_000_000,
                payload: b"payload with provenance",
                provenance: Some(provenance.clone()),
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
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                payload: b"hello",
                provenance: None,
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
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                payload: b"original",
                provenance: None,
            },
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
            &InnerEnvelopeParams {
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                payload: b"data",
                provenance: Some(provenance),
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
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                payload: b"data",
                provenance: None,
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
        let expected = Sha256::digest([0x00]).to_vec();
        let hash = compute_provenance_hash(None).unwrap();
        assert_eq!(hash, expected);
    }

    #[tokio::test]
    async fn inner_envelope_serializes_with_msgpack() {
        let (custody, signing_key) = setup().await;

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                payload: b"msgpack test",
                provenance: None,
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
        assert_eq!(envelope.signature, deserialized.signature);
    }

    #[tokio::test]
    async fn verify_invalid_pubkey_length_returns_error() {
        let (custody, signing_key) = setup().await;

        let envelope = create_inner_envelope(
            &InnerEnvelopeParams {
                context_id: "ctx-1",
                sender_did: "did:dht:alice",
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                payload: b"test",
                provenance: None,
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
        let payload_hash = Sha256::digest(b"test").to_vec();
        let provenance_hash = Sha256::digest([0x00]).to_vec();

        // Hash with the real domain separator (via the production function).
        let params = InnerEnvelopeParams {
            context_id: "ctx-1",
            sender_did: "did:dht:alice",
            epoch: 1,
            generation: 0,
            sequence: 1,
            timestamp: 1_700_000_000,
            payload: b"test",
            provenance: None,
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
            h.update(&payload_hash);
            h.update(&provenance_hash);
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
                            context_id: "ctx-prop",
                            sender_did: "did:dht:proptest",
                            epoch: 1,
                            generation: 0,
                            sequence: 1,
                            timestamp: 1_700_000_000,
                            payload: &payload,
                            provenance: None,
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
    }
}
