//! Outer envelope construction, serialization, and high-level seal/open
//! operations.
//!
//! The outer envelope is the wire format visible to relays and the network.
//! It is deliberately minimal to limit metadata exposure: relays see only a
//! pseudonym-based `routing_id`, an optional `recipient_hint`, a `blob_ttl`,
//! and an opaque `encrypted_blob`.
//!
//! # High-level operations
//!
//! - [`seal_envelope`] — The primary send-path function. Serializes an inner
//!   envelope, encrypts via MLS, and wraps in an outer envelope.
//! - [`open_envelope`] — The primary receive-path function. Decrypts the outer
//!   envelope's blob via MLS, deserializes and verifies the inner envelope.
//!
//! See ADR-002 in `.docs/adrs/phase-1.md` for the full outer envelope design.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::EnvelopeError;
use super::inner::{InnerEnvelope, verify_inner_signature};
use super::padding::strip_padding;
use crate::crypto::mls::encrypt::{decrypt, encrypt, serialize_ciphertext};
use crate::crypto::mls::group::ScpMlsGroup;

/// The outer envelope — the minimal wire format visible to relays.
///
/// Relays route by `routing_id`, store for `blob_ttl` seconds, and delete.
/// They learn nothing about the sender, context, or message content.
///
/// Binary fields use `serde_bytes` for efficient `MessagePack` encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuterEnvelope {
    /// Per-context pseudonym derived via `HMAC-SHA256`. Used as the routing
    /// key by relays. 32 bytes.
    #[serde(with = "serde_bytes")]
    pub routing_id: Vec<u8>,

    /// Recipient pseudonym for directed messages, or `None` for broadcast.
    /// 32 bytes when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_hint: Option<Vec<u8>>,

    /// How long (in seconds) the relay should store this envelope before
    /// deletion.
    pub blob_ttl: u32,

    /// The MLS-encrypted blob containing the serialized inner envelope.
    #[serde(with = "serde_bytes")]
    pub encrypted_blob: Vec<u8>,
}

/// Constructs an outer envelope from its components.
///
/// This is a straightforward constructor — no encryption or signing happens
/// here. The `encrypted_blob` should already be the MLS-encrypted inner
/// envelope.
///
/// # Errors
///
/// Returns [`EnvelopeError::InvalidRoutingId`] if `routing_id` is not 32 bytes.
/// Returns [`EnvelopeError::InvalidRecipientHint`] if `recipient_hint` is
/// present but not 32 bytes.
pub fn create_outer_envelope(
    routing_id: &[u8],
    recipient_hint: Option<&[u8]>,
    blob_ttl: u32,
    encrypted_blob: Vec<u8>,
) -> Result<OuterEnvelope, EnvelopeError> {
    if routing_id.len() != 32 {
        return Err(EnvelopeError::InvalidRoutingId(format!(
            "routing_id must be 32 bytes, got {}",
            routing_id.len()
        )));
    }

    if let Some(hint) = recipient_hint
        && hint.len() != 32
    {
        return Err(EnvelopeError::InvalidRecipientHint(format!(
            "recipient_hint must be 32 bytes, got {}",
            hint.len()
        )));
    }

    Ok(OuterEnvelope {
        routing_id: routing_id.to_vec(),
        recipient_hint: recipient_hint.map(<[u8]>::to_vec),
        blob_ttl,
        encrypted_blob,
    })
}

impl OuterEnvelope {
    /// Serializes this outer envelope to `MessagePack` binary format.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::SerializationFailed`] if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        rmp_serde::to_vec_named(self).map_err(|e| EnvelopeError::SerializationFailed(e.to_string()))
    }

    /// Deserializes an outer envelope from `MessagePack` binary format.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::DeserializationFailed`] if the bytes are not
    /// a valid `MessagePack`-encoded `OuterEnvelope`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        rmp_serde::from_slice(bytes)
            .map_err(|e| EnvelopeError::DeserializationFailed(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// High-level send / receive path
// ---------------------------------------------------------------------------

/// Seals an inner envelope for transmission: serializes, encrypts via MLS,
/// and wraps in an outer envelope.
///
/// This is the primary **send-path** function. The caller is responsible for
/// constructing the [`InnerEnvelope`] (via [`create_inner_envelope`]) and
/// providing the routing metadata for the outer envelope.
///
/// # Processing order
///
/// 1. Serialize the inner envelope to `MessagePack`.
/// 2. Encrypt the serialized bytes via MLS (`create_message` +
///    TLS-serialize).
/// 3. Wrap the ciphertext in an [`OuterEnvelope`] with the provided routing
///    metadata.
///
/// # Arguments
///
/// * `inner` - The fully constructed inner envelope (already signed and
///   padded).
/// * `group` - The MLS group to encrypt within. Must be active.
/// * `routing_id` - 32-byte per-context pseudonym for relay routing.
/// * `recipient_hint` - Optional 32-byte recipient pseudonym for directed
///   messages, or `None` for broadcast.
/// * `blob_ttl` - How long (seconds) the relay should store the envelope.
///
/// # Errors
///
/// Returns [`EnvelopeError::SerializationFailed`] if inner envelope
/// serialization fails.
/// Returns [`EnvelopeError::MlsEncryptionFailed`] if MLS encryption fails.
/// Returns [`EnvelopeError::InvalidRoutingId`] if `routing_id` is not 32
/// bytes.
/// Returns [`EnvelopeError::InvalidRecipientHint`] if `recipient_hint` is
/// present but not 32 bytes.
///
/// See ADR-002 acceptance criterion 4.
///
/// [`create_inner_envelope`]: super::inner::create_inner_envelope
pub fn seal_envelope(
    inner: &InnerEnvelope,
    group: &mut ScpMlsGroup,
    routing_id: &[u8],
    recipient_hint: Option<&[u8]>,
    blob_ttl: u32,
) -> Result<OuterEnvelope, EnvelopeError> {
    // 1. Serialize inner envelope to MessagePack.
    let serialized = rmp_serde::to_vec_named(inner)
        .map_err(|e| EnvelopeError::SerializationFailed(e.to_string()))?;

    // 2. Encrypt via MLS.
    let mls_message = encrypt(group, &serialized)
        .map_err(|e| EnvelopeError::MlsEncryptionFailed(e.to_string()))?;

    let encrypted_blob = serialize_ciphertext(&mls_message)
        .map_err(|e| EnvelopeError::MlsEncryptionFailed(e.to_string()))?;

    // 3. Wrap in outer envelope.
    create_outer_envelope(routing_id, recipient_hint, blob_ttl, encrypted_blob)
}

/// Opens a received outer envelope: decrypts via MLS, deserializes,
/// strips padding, verifies content integrity, and verifies the inner
/// signature.
///
/// This is the primary **receive-path** function with full integrity
/// verification. It rejects messages that fail any verification step.
///
/// # Processing order
///
/// 1. Decrypt the `encrypted_blob` via MLS (membership tag verification and
///    generation-number replay prevention are enforced by the MLS layer).
/// 2. Deserialize the plaintext bytes into an [`InnerEnvelope`].
/// 3. Strip bucket padding from the payload to recover the original
///    plaintext.
/// 4. Verify `payload_hash == SHA-256(stripped_payload)` — reject on content
///    integrity failure.
/// 5. Verify the inner Ed25519 signature against the sender's public key —
///    reject on signature mismatch.
/// 6. Return the verified inner envelope.
///
/// # Arguments
///
/// * `outer` - The received outer envelope.
/// * `group` - The MLS group to decrypt within. Must be active.
/// * `sender_public_key` - The sender's Ed25519 public key (32 bytes),
///   resolved from the `sender_did` in the inner envelope.
///
/// # Errors
///
/// Returns [`EnvelopeError::MlsDecryptionFailed`] if MLS decryption fails
/// (including replay rejection via generation number).
/// Returns [`EnvelopeError::DeserializationFailed`] if the decrypted bytes
/// are not a valid inner envelope.
/// Returns [`EnvelopeError::InvalidPadding`] if padding cannot be stripped.
/// Returns [`EnvelopeError::ContentIntegrityFailed`] if `payload_hash` does
/// not match `SHA-256(stripped_payload)`.
/// Returns [`EnvelopeError::VerificationFailed`] if the public key or
/// signature bytes are malformed.
/// Returns [`EnvelopeError::InnerSignatureMismatch`] if the signature is
/// well-formed but does not match.
///
/// See ADR-002 acceptance criterion 5.
pub fn open_envelope(
    outer: &OuterEnvelope,
    group: &mut ScpMlsGroup,
    sender_public_key: &[u8],
) -> Result<InnerEnvelope, EnvelopeError> {
    // 1. MLS decrypt (membership tag + generation number verified by MLS).
    let plaintext = decrypt(group, &outer.encrypted_blob)
        .map_err(|e| EnvelopeError::MlsDecryptionFailed(e.to_string()))?;

    // 2. Deserialize inner envelope.
    let inner: InnerEnvelope = rmp_serde::from_slice(&plaintext)
        .map_err(|e| EnvelopeError::DeserializationFailed(e.to_string()))?;

    // 3. Strip padding to recover original payload.
    let stripped_payload = strip_padding(&inner.payload)?;

    // 4. Verify content integrity: payload_hash == SHA-256(stripped_payload).
    let computed_hash = Sha256::digest(&stripped_payload);
    if computed_hash.as_slice() != inner.payload_hash.as_slice() {
        return Err(EnvelopeError::ContentIntegrityFailed);
    }

    // 5. Verify inner signature.
    let valid = verify_inner_signature(&inner, sender_public_key)?;
    if !valid {
        return Err(EnvelopeError::InnerSignatureMismatch);
    }

    // 6. Return the verified inner envelope.
    Ok(inner)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn create_outer_envelope_broadcast() {
        let routing_id = [0xAA; 32];
        let blob = vec![0x01, 0x02, 0x03];

        let envelope = create_outer_envelope(&routing_id, None, 3600, blob.clone()).unwrap();

        assert_eq!(envelope.routing_id, routing_id);
        assert!(envelope.recipient_hint.is_none());
        assert_eq!(envelope.blob_ttl, 3600);
        assert_eq!(envelope.encrypted_blob, blob);
    }

    #[test]
    fn create_outer_envelope_directed() {
        let routing_id = [0xAA; 32];
        let recipient = [0xBB; 32];
        let blob = vec![0x01];

        let envelope = create_outer_envelope(&routing_id, Some(&recipient), 7200, blob).unwrap();

        assert_eq!(
            envelope.recipient_hint.as_deref(),
            Some(recipient.as_slice())
        );
    }

    #[test]
    fn create_outer_envelope_invalid_routing_id() {
        let result = create_outer_envelope(&[0xAA; 16], None, 3600, vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn create_outer_envelope_invalid_recipient_hint() {
        let result = create_outer_envelope(&[0xAA; 32], Some(&[0xBB; 16]), 3600, vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn outer_envelope_msgpack_roundtrip() {
        let routing_id = [0xAA; 32];
        let recipient = [0xBB; 32];
        let blob = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let envelope = create_outer_envelope(&routing_id, Some(&recipient), 3600, blob).unwrap();

        let bytes = envelope.to_bytes().unwrap();
        let restored = OuterEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(envelope.routing_id, restored.routing_id);
        assert_eq!(envelope.recipient_hint, restored.recipient_hint);
        assert_eq!(envelope.blob_ttl, restored.blob_ttl);
        assert_eq!(envelope.encrypted_blob, restored.encrypted_blob);
    }

    #[test]
    fn outer_envelope_msgpack_roundtrip_no_recipient() {
        let envelope = create_outer_envelope(&[0xAA; 32], None, 60, vec![0x00]).unwrap();

        let bytes = envelope.to_bytes().unwrap();
        let restored = OuterEnvelope::from_bytes(&bytes).unwrap();

        assert!(restored.recipient_hint.is_none());
    }
}

/// Integration tests for the high-level seal/open envelope operations.
///
/// These tests exercise the full send → receive pipeline including MLS
/// encryption/decryption, inner envelope serialization, padding, content
/// integrity verification, and signature verification.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod seal_open_tests {
    use openmls::prelude::*;
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::{KeyCustody, KeyType};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::crypto::mls::credential::ScpCredential;
    use crate::crypto::mls::group::{add_member, create_group, generate_key_package, join_group};
    use crate::envelope::inner::{Provenance, create_inner_envelope};
    use crate::envelope::padding::strip_padding;

    fn test_credential(name: &str) -> ScpCredential {
        ScpCredential::new(format!("did:dht:z6Mk{name}"), None)
    }

    /// Sets up Alice and Bob in a shared MLS group.
    /// Returns (`alice_group`, `bob_group`).
    fn setup_mls_groups() -> (ScpMlsGroup, ScpMlsGroup) {
        let alice_cred = test_credential("alice");
        let mut alice_group = create_group(&alice_cred).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, bob_signer, bob_provider) = generate_key_package(&bob_cred).unwrap();
        let bob_kp: KeyPackageIn = bob_kp_bundle.key_package().clone().into();

        let add_result = add_member(&mut alice_group, bob_kp).unwrap();
        let bob_group = join_group(&add_result.welcome, bob_provider, bob_signer).unwrap();

        (alice_group, bob_group)
    }

    /// Creates an inner envelope signed by Alice's key for use in tests.
    async fn create_test_inner(
        payload: &[u8],
        provenance: Option<Provenance>,
    ) -> (InnerEnvelope, Vec<u8>) {
        let custody = InMemoryKeyCustody::new();
        let signing_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        let inner = create_inner_envelope(
            "ctx-1",
            "did:dht:z6Mkalice",
            1,
            0,
            1,
            1_700_000_000,
            payload,
            provenance,
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        (inner, pubkey.as_bytes().to_vec())
    }

    // -----------------------------------------------------------------------
    // seal_envelope tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn seal_envelope_produces_valid_outer_envelope() {
        let (mut alice_group, _bob_group) = setup_mls_groups();
        let (inner, _pubkey) = create_test_inner(b"hello world", None).await;
        let routing_id = [0xAA; 32];

        let outer = seal_envelope(&inner, &mut alice_group, &routing_id, None, 3600).unwrap();

        assert_eq!(outer.routing_id, routing_id);
        assert!(outer.recipient_hint.is_none());
        assert_eq!(outer.blob_ttl, 3600);
        assert!(
            !outer.encrypted_blob.is_empty(),
            "encrypted_blob must not be empty"
        );
    }

    #[tokio::test]
    async fn seal_envelope_with_recipient_hint() {
        let (mut alice_group, _bob_group) = setup_mls_groups();
        let (inner, _pubkey) = create_test_inner(b"directed message", None).await;
        let routing_id = [0xAA; 32];
        let recipient = [0xBB; 32];

        let outer = seal_envelope(
            &inner,
            &mut alice_group,
            &routing_id,
            Some(&recipient),
            7200,
        )
        .unwrap();

        assert_eq!(outer.recipient_hint.as_deref(), Some(recipient.as_slice()));
        assert_eq!(outer.blob_ttl, 7200);
    }

    #[tokio::test]
    async fn seal_envelope_rejects_invalid_routing_id() {
        let (mut alice_group, _bob_group) = setup_mls_groups();
        let (inner, _pubkey) = create_test_inner(b"test", None).await;

        let result = seal_envelope(&inner, &mut alice_group, &[0xAA; 16], None, 3600);
        assert!(result.is_err(), "should reject 16-byte routing_id");
    }

    // -----------------------------------------------------------------------
    // open_envelope tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn seal_then_open_roundtrip_produces_original_content() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();
        let original_payload = b"hello, sealed world!";
        let (inner, pubkey) = create_test_inner(original_payload, None).await;
        let routing_id = [0xAA; 32];

        // Seal (Alice sends).
        let outer = seal_envelope(&inner, &mut alice_group, &routing_id, None, 3600).unwrap();

        // Open (Bob receives).
        let recovered = open_envelope(&outer, &mut bob_group, &pubkey).unwrap();

        // Verify all inner envelope fields match.
        assert_eq!(recovered.context_id, inner.context_id);
        assert_eq!(recovered.sender_did, inner.sender_did);
        assert_eq!(recovered.epoch, inner.epoch);
        assert_eq!(recovered.generation, inner.generation);
        assert_eq!(recovered.sequence, inner.sequence);
        assert_eq!(recovered.timestamp, inner.timestamp);
        assert_eq!(recovered.payload_hash, inner.payload_hash);
        assert_eq!(recovered.payload, inner.payload);
        assert_eq!(recovered.signature, inner.signature);

        // Verify we can strip padding to recover original payload.
        let stripped = strip_padding(&recovered.payload).unwrap();
        assert_eq!(stripped, original_payload);
    }

    #[tokio::test]
    async fn seal_then_open_roundtrip_with_provenance() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();
        let provenance = Provenance {
            source: "test-tool".into(),
            upstream_hash: Some("abc123".into()),
        };
        let (inner, pubkey) =
            create_test_inner(b"payload with provenance", Some(provenance.clone())).await;
        let routing_id = [0xAA; 32];

        let outer = seal_envelope(&inner, &mut alice_group, &routing_id, None, 3600).unwrap();
        let recovered = open_envelope(&outer, &mut bob_group, &pubkey).unwrap();

        assert_eq!(recovered.provenance, Some(provenance));
        assert_eq!(recovered.provenance_hash, inner.provenance_hash);
    }

    #[tokio::test]
    #[should_panic(expected = "Ciphertext decryption failed")]
    async fn open_envelope_rejects_tampered_encrypted_blob() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();
        let (inner, pubkey) = create_test_inner(b"test", None).await;
        let routing_id = [0xAA; 32];

        let mut outer = seal_envelope(&inner, &mut alice_group, &routing_id, None, 3600).unwrap();

        // Tamper with the encrypted blob.
        if let Some(byte) = outer.encrypted_blob.last_mut() {
            *byte ^= 0xFF;
        }

        // OpenMLS panics internally on AEAD decryption failure rather than
        // returning an error. This is a known upstream behavior.
        let _result = open_envelope(&outer, &mut bob_group, &pubkey);
    }

    #[tokio::test]
    async fn open_envelope_rejects_mismatched_payload_hash() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();
        let custody = InMemoryKeyCustody::new();
        let signing_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&signing_key).await.unwrap();

        // Create a legitimate inner envelope.
        let mut inner = create_inner_envelope(
            "ctx-1",
            "did:dht:z6Mkalice",
            1,
            0,
            1,
            1_700_000_000,
            b"original data",
            None,
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        // Tamper with payload_hash (this also breaks the signature, but
        // content integrity check runs first).
        inner.payload_hash = vec![0xFF; 32];

        let routing_id = [0xAA; 32];
        let outer = seal_envelope(&inner, &mut alice_group, &routing_id, None, 3600).unwrap();

        let result = open_envelope(&outer, &mut bob_group, pubkey.as_bytes());
        assert!(
            result.is_err(),
            "open_envelope must reject mismatched payload_hash"
        );

        // Verify it's specifically a content integrity error.
        let err_msg = format!("{result:?}");
        assert!(
            err_msg.contains("ContentIntegrityFailed"),
            "error should be ContentIntegrityFailed, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn open_envelope_rejects_wrong_sender_key() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();
        let (inner, _correct_pubkey) = create_test_inner(b"signed by alice", None).await;
        let routing_id = [0xAA; 32];

        let outer = seal_envelope(&inner, &mut alice_group, &routing_id, None, 3600).unwrap();

        // Use a different key for verification.
        let other_custody = InMemoryKeyCustody::new();
        let other_key = other_custody
            .generate_keypair(KeyType::Ed25519)
            .await
            .unwrap();
        let wrong_pubkey = other_custody.public_key(&other_key).await.unwrap();

        let result = open_envelope(&outer, &mut bob_group, wrong_pubkey.as_bytes());
        assert!(
            result.is_err(),
            "open_envelope must reject wrong sender public key"
        );

        let err_msg = format!("{result:?}");
        assert!(
            err_msg.contains("InnerSignatureMismatch"),
            "error should be InnerSignatureMismatch, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn open_envelope_rejects_replayed_message() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();
        let (inner, pubkey) = create_test_inner(b"replay me", None).await;
        let routing_id = [0xAA; 32];

        let outer = seal_envelope(&inner, &mut alice_group, &routing_id, None, 3600).unwrap();

        // First open succeeds.
        let _recovered = open_envelope(&outer, &mut bob_group, &pubkey).unwrap();

        // Second open with same ciphertext should fail (MLS generation
        // number replay prevention).
        let replay_result = open_envelope(&outer, &mut bob_group, &pubkey);
        assert!(
            replay_result.is_err(),
            "open_envelope must reject replayed ciphertext"
        );
    }

    #[tokio::test]
    async fn open_envelope_rejects_garbage_encrypted_blob() {
        let (_alice_group, mut bob_group) = setup_mls_groups();
        let routing_id = [0xAA; 32];

        let outer =
            create_outer_envelope(&routing_id, None, 3600, vec![0xDE, 0xAD, 0xBE, 0xEF]).unwrap();

        let result = open_envelope(&outer, &mut bob_group, &[0u8; 32]);
        assert!(
            result.is_err(),
            "open_envelope must reject garbage encrypted_blob"
        );
    }

    #[tokio::test]
    async fn seal_then_open_empty_payload_roundtrip() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();
        let (inner, pubkey) = create_test_inner(b"", None).await;
        let routing_id = [0xAA; 32];

        let outer = seal_envelope(&inner, &mut alice_group, &routing_id, None, 3600).unwrap();
        let recovered = open_envelope(&outer, &mut bob_group, &pubkey).unwrap();

        let stripped = strip_padding(&recovered.payload).unwrap();
        assert!(stripped.is_empty(), "empty payload should roundtrip");

        // Verify payload_hash matches SHA-256 of empty bytes.
        let expected_hash = Sha256::digest(b"").to_vec();
        assert_eq!(recovered.payload_hash, expected_hash);
    }

    #[tokio::test]
    async fn seal_then_open_multiple_messages() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();
        let routing_id = [0xAA; 32];

        let messages: &[&[u8]] = &[b"first", b"second", b"third"];

        // Seal all messages.
        let mut outers = Vec::new();
        let mut pubkeys = Vec::new();
        for msg in messages {
            let (inner, pubkey) = create_test_inner(msg, None).await;
            let outer = seal_envelope(&inner, &mut alice_group, &routing_id, None, 3600).unwrap();
            outers.push(outer);
            pubkeys.push(pubkey);
        }

        // Open all messages in order.
        for (i, (outer, pubkey)) in outers.iter().zip(pubkeys.iter()).enumerate() {
            let recovered = open_envelope(outer, &mut bob_group, pubkey).unwrap();
            let stripped = strip_padding(&recovered.payload).unwrap();
            assert_eq!(
                stripped, messages[i],
                "message {i} must roundtrip correctly"
            );
        }
    }

    mod proptest_seal_open {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(10))]
            #[test]
            fn seal_open_roundtrip_arbitrary(
                payload in proptest::collection::vec(any::<u8>(), 0..4000)
            ) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let (mut alice_group, mut bob_group) = setup_mls_groups();
                    let (inner, pubkey) = create_test_inner(&payload, None).await;
                    let routing_id = [0xAA; 32];

                    let outer = seal_envelope(
                        &inner,
                        &mut alice_group,
                        &routing_id,
                        None,
                        3600,
                    ).unwrap();

                    let recovered = open_envelope(
                        &outer,
                        &mut bob_group,
                        &pubkey,
                    ).unwrap();

                    let stripped = strip_padding(&recovered.payload).unwrap();
                    prop_assert_eq!(stripped, payload);

                    Ok(())
                })?;
            }
        }
    }
}
