//! Async inner envelope creation (signing).
//!
//! This module contains [`create_inner_envelope`], the only async function in
//! the inner envelope subsystem. It is separated from the pure sync types and
//! verification logic in the parent module to support clean extraction into
//! `scp-protocol` (#1446).

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use scp_platform::traits::{KeyCustody, KeyHandle};

use super::{InnerEnvelope, InnerEnvelopeParams, SCP_INNER_ENVELOPE_VERSION};
use scp_protocol::envelope::EnvelopeError;

// These functions are in the inner envelope module.
use scp_protocol::envelope::inner::{compute_canonical_hash, compute_provenance_hash};
use scp_protocol::envelope::padding::pad_to_bucket;

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
// Sync variant: sign with raw Ed25519 key
// ---------------------------------------------------------------------------

/// Creates an inner envelope signed with a raw Ed25519 signing key.
///
/// Sync variant of [`create_inner_envelope`] for use in
/// `ContextManager::send_message` where the signing key is available
/// directly (not behind a `KeyCustody` abstraction).
///
/// # Processing order
///
/// 1. Compute `payload_hash = SHA-256(payload)`.
/// 2. Compute `provenance_hash`.
/// 3. Compute canonical hash.
/// 4. Sign with the provided `signing_key`.
/// 5. Pad payload to bucket boundary.
/// 6. Return the complete inner envelope.
///
/// # Errors
///
/// Returns [`EnvelopeError::SerializationFailed`] if provenance serialization fails.
/// Returns [`EnvelopeError::PayloadTooLarge`] if the payload exceeds the maximum
/// bucket size.
pub fn create_inner_envelope_raw(
    params: &InnerEnvelopeParams<'_>,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<InnerEnvelope, EnvelopeError> {
    // 1. Hash original plaintext.
    let payload_hash: [u8; 32] = Sha256::digest(params.payload).into();

    // 2. Hash provenance.
    let provenance_hash: [u8; 32] = compute_provenance_hash(params.provenance.as_ref())?;

    // 3. Compute canonical hash for signing.
    let canonical_hash = compute_canonical_hash(params, &payload_hash, &provenance_hash);

    // 4. Sign the canonical hash.
    let signature = ed25519_dalek::Signer::sign(signing_key, &canonical_hash);

    // 5. Pad payload to bucket boundary.
    let padded_payload = pad_to_bucket(params.payload)?;

    // 6. Build and return the envelope.
    let sig_bytes: [u8; 64] = signature.to_bytes();

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
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::envelope::inner::{
        MessageType, Provenance, enforce_inner_envelope_category_a, validate_inner_version,
        verify_inner_signature,
    };
    use scp_protocol::envelope::padding::strip_padding;
    use scp_protocol::identity::SigningKeyId;

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

        // Category A action signed by agent key -> rejected.
        let result = enforce_inner_envelope_category_a(&envelope, "did_document");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, EnvelopeError::CategoryAViolation(_)),
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

        // Category B action signed by agent key -> accepted.
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

        // Category A action signed by active key -> accepted.
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
            #[serde(with = "scp_protocol::serde_util::serde_bounded_string")]
            context_id: String,
            #[serde(with = "scp_protocol::serde_util::serde_bounded_string")]
            sender_did: String,
            epoch: u64,
            generation: u64,
            sequence: u64,
            timestamp: u64,
            message_type: MessageType,
            #[serde(with = "scp_protocol::serde_util::serde_hash_32")]
            payload_hash: [u8; 32],
            #[serde(with = "scp_protocol::serde_util::serde_bounded_bytes")]
            payload: Vec<u8>,
            provenance: Option<Provenance>,
            #[serde(with = "scp_protocol::serde_util::serde_hash_32")]
            provenance_hash: [u8; 32],
            signing_key_id: SigningKeyId,
            #[serde(with = "scp_protocol::serde_util::serde_signature_64")]
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
