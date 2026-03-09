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
//!   The sender's Ed25519 public key is resolved internally from the MLS group
//!   state (SCP-177).
//!
//! See ADR-002 in `.docs/adrs/phase-1.md` for the full outer envelope design.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::EnvelopeError;
use super::inner::{InnerEnvelope, verify_inner_signature};
use super::padding::strip_padding;
use crate::crypto::mls::encrypt::{decrypt_with_sender_key, encrypt, serialize_ciphertext};
use crate::crypto::mls::group::ScpMlsGroup;
use crate::crypto::sender_keys::SenderKey;
use crate::crypto::sender_keys::encrypt::{decrypt_sender_layer, encrypt_sender_layer};

/// The outer envelope — the minimal wire format visible to relays.
///
/// Relays route by `routing_id`, store for `blob_ttl` seconds, and delete.
/// They learn nothing about the sender, context, or message content.
///
/// Binary fields use `serde_bytes` for efficient `MessagePack` encoding.
/// The current SCP protocol version for outer envelopes.
///
/// See spec §13.2.3 for outer envelope versioning.
pub const SCP_OUTER_ENVELOPE_VERSION: u16 = super::SCP_PROTOCOL_VERSION;

/// Serde default for the `version` field on [`OuterEnvelope`].
const fn default_outer_version() -> u16 {
    super::SCP_PROTOCOL_VERSION
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OuterEnvelope {
    /// Protocol version (§13.2.3). SCP/1.0 = `0x0100`.
    /// Used for deserialization routing — tells the recipient which version's
    /// deserializer to use. Since the outer envelope is unsigned, this is
    /// purely informational.
    #[serde(default = "default_outer_version")]
    pub version: u16,

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
    /// Bounded to 512 KiB on deserialization to prevent OOM (#347).
    #[serde(with = "crate::serde_util::serde_bounded_bytes")]
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
        version: super::SCP_PROTOCOL_VERSION,
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
    /// Performs a pre-deserialization size check against
    /// [`MAX_ENVELOPE_SIZE`] to reject obviously oversized inputs before the
    /// deserializer allocates memory (#347). Individual fields are further
    /// bounded by serde-level helpers (e.g., `serde_bounded_bytes` for
    /// `encrypted_blob`).
    ///
    /// [`MAX_ENVELOPE_SIZE`]: crate::serde_util::MAX_ENVELOPE_SIZE
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::EnvelopeTooLarge`] if `bytes.len()` exceeds
    /// `MAX_ENVELOPE_SIZE`.
    /// Returns [`EnvelopeError::DeserializationFailed`] if the bytes are not
    /// a valid `MessagePack`-encoded `OuterEnvelope`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        use crate::serde_util::MAX_ENVELOPE_SIZE;

        if bytes.len() > MAX_ENVELOPE_SIZE {
            return Err(EnvelopeError::EnvelopeTooLarge {
                size: bytes.len(),
                max: MAX_ENVELOPE_SIZE,
            });
        }
        let envelope: Self = rmp_serde::from_slice(bytes)
            .map_err(|e| EnvelopeError::DeserializationFailed(e.to_string()))?;
        if envelope.version != SCP_OUTER_ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion {
                version: envelope.version,
            });
        }
        Ok(envelope)
    }

    /// Validates that this outer envelope's version field is supported (§13.2.3).
    ///
    /// Currently only SCP/1.0 (`0x0100`) is recognized. Call this after
    /// deserialization to reject envelopes from incompatible protocol versions.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::UnsupportedVersion`] if `self.version` is not
    /// `SCP_PROTOCOL_VERSION`.
    pub const fn validate_version(&self) -> Result<(), EnvelopeError> {
        if self.version != super::SCP_PROTOCOL_VERSION {
            return Err(EnvelopeError::UnsupportedVersion {
                version: self.version,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// High-level send / receive path
// ---------------------------------------------------------------------------

/// Seals an inner envelope for transmission: serializes, encrypts with the
/// sender key layer, encrypts via MLS, and wraps in an outer envelope.
///
/// This is the primary **send-path** function. The caller is responsible for
/// constructing the [`InnerEnvelope`] (via [`create_inner_envelope`]) and
/// providing the routing metadata for the outer envelope.
///
/// # Processing order
///
/// 1. Serialize the inner envelope to `MessagePack`.
/// 2. Encrypt the serialized bytes with the sender's AES-256-GCM key
///    (per-sender forward secrecy layer — see ADR-007).
/// 3. Encrypt the sender-key ciphertext via MLS (`create_message` +
///    TLS-serialize).
/// 4. Wrap the MLS ciphertext in an [`OuterEnvelope`] with the provided
///    routing metadata.
///
/// # Arguments
///
/// * `inner` - The fully constructed inner envelope (already signed and
///   padded).
/// * `group` - The MLS group to encrypt within. Must be active.
/// * `sender_key` - The sender's current AES-256 sender key for this
///   context.
/// * `routing_id` - 32-byte per-context pseudonym for relay routing.
/// * `recipient_hint` - Optional 32-byte recipient pseudonym for directed
///   messages, or `None` for broadcast.
/// * `blob_ttl` - How long (seconds) the relay should store the envelope.
///
/// # Errors
///
/// Returns [`EnvelopeError::SerializationFailed`] if inner envelope
/// serialization fails.
/// Returns [`EnvelopeError::SenderKeyEncryptionFailed`] if sender key
/// AES-256-GCM encryption fails.
/// Returns [`EnvelopeError::MlsEncryptionFailed`] if MLS encryption fails.
/// Returns [`EnvelopeError::InvalidRoutingId`] if `routing_id` is not 32
/// bytes.
/// Returns [`EnvelopeError::InvalidRecipientHint`] if `recipient_hint` is
/// present but not 32 bytes.
///
/// See ADR-002 acceptance criterion 4 and ADR-007.
///
/// [`create_inner_envelope`]: super::inner::create_inner_envelope
pub fn seal_envelope(
    inner: &InnerEnvelope,
    group: &mut ScpMlsGroup,
    sender_key: &SenderKey,
    routing_id: &[u8],
    recipient_hint: Option<&[u8]>,
    blob_ttl: u32,
) -> Result<OuterEnvelope, EnvelopeError> {
    // 1. Serialize inner envelope to MessagePack.
    let serialized = rmp_serde::to_vec_named(inner)
        .map_err(|e| EnvelopeError::SerializationFailed(e.to_string()))?;

    // 2. Encrypt with sender key (AES-256-GCM), binding context metadata as AAD.
    let sender_encrypted = encrypt_sender_layer(
        sender_key,
        &serialized,
        &inner.context_id,
        &inner.sender_did,
        inner.epoch,
        inner.sequence,
    )
    .map_err(|e| EnvelopeError::SenderKeyEncryptionFailed(e.to_string()))?;

    // 3. Encrypt via MLS.
    let mls_message = encrypt(group, &sender_encrypted)
        .map_err(|e| EnvelopeError::MlsEncryptionFailed(e.to_string()))?;

    let encrypted_blob = serialize_ciphertext(&mls_message)
        .map_err(|e| EnvelopeError::MlsEncryptionFailed(e.to_string()))?;

    // 4. Wrap in outer envelope.
    create_outer_envelope(routing_id, recipient_hint, blob_ttl, encrypted_blob)
}

/// Opens a received outer envelope: decrypts via MLS, decrypts with the
/// sender key, deserializes, strips padding, verifies content integrity,
/// and verifies the inner signature.
///
/// This is the primary **receive-path** function with full integrity
/// verification. It rejects messages that fail any verification step.
///
/// The sender's Ed25519 public key is resolved internally from the MLS
/// group state — the caller does not need to supply it. This prevents
/// callers from accidentally providing the wrong key. See SCP-177.
///
/// # Processing order
///
/// 1. Decrypt the `encrypted_blob` via MLS and extract the sender's
///    signature key from the MLS group tree (membership tag verification and
///    generation-number replay prevention are enforced by the MLS layer).
/// 2. Decrypt the MLS plaintext with the sender's AES-256-GCM key
///    (per-sender forward secrecy layer — see ADR-007).
/// 3. Deserialize the sender-key-decrypted bytes into an [`InnerEnvelope`].
/// 4. Verify the inner envelope's `sender_did` is a member of the MLS group.
/// 5. Strip bucket padding from the payload to recover the original
///    plaintext.
/// 6. Verify `payload_hash == SHA-256(stripped_payload)` — reject on content
///    integrity failure.
/// 7. Verify the inner Ed25519 signature against the sender's public key
///    (resolved from MLS) — reject on signature mismatch.
/// 8. Return the verified inner envelope.
///
/// # Arguments
///
/// * `outer` - The received outer envelope.
/// * `group` - The MLS group to decrypt within. Must be active.
/// * `sender_key` - The sender's current AES-256 sender key for this
///   context.
///
/// # Errors
///
/// Returns [`EnvelopeError::MlsDecryptionFailed`] if MLS decryption fails
/// (including replay rejection via generation number).
/// Returns [`EnvelopeError::SenderKeyDecryptionFailed`] if sender key
/// AES-256-GCM decryption fails (wrong key, tampered, or corrupted).
/// Returns [`EnvelopeError::DeserializationFailed`] if the decrypted bytes
/// are not a valid inner envelope.
/// Returns [`EnvelopeError::UnknownSender`] if the inner envelope's
/// `sender_did` is not found in the MLS group member list.
/// Returns [`EnvelopeError::InvalidPadding`] if padding cannot be stripped.
/// Returns [`EnvelopeError::ContentIntegrityFailed`] if `payload_hash` does
/// not match `SHA-256(stripped_payload)`.
/// Returns [`EnvelopeError::VerificationFailed`] if the public key or
/// signature bytes are malformed.
/// Returns [`EnvelopeError::InnerSignatureMismatch`] if the signature is
/// well-formed but does not match.
///
/// See ADR-002 acceptance criterion 5, ADR-007, and SCP-177.
pub fn open_envelope(
    outer: &OuterEnvelope,
    group: &mut ScpMlsGroup,
    sender_key: &SenderKey,
    context_id: &str,
    sender_did: &str,
    epoch: u64,
    sequence: u64,
) -> Result<InnerEnvelope, EnvelopeError> {
    // 1. MLS decrypt and extract sender's signature key from MLS tree.
    let (mls_plaintext, sender_public_key) = decrypt_with_sender_key(group, &outer.encrypted_blob)
        .map_err(|e| EnvelopeError::MlsDecryptionFailed(e.to_string()))?;

    // 2. Decrypt sender key layer (AES-256-GCM), verifying AAD binding.
    let plaintext = decrypt_sender_layer(
        sender_key,
        &mls_plaintext,
        context_id,
        sender_did,
        epoch,
        sequence,
    )
    .map_err(|e| EnvelopeError::SenderKeyDecryptionFailed(e.to_string()))?;

    // 3. Size-check then deserialize inner envelope (#347).
    //    Defense in depth: reject oversized decrypted payloads before
    //    deserializing. The BOUNDED_BYTES_MAX limit on `encrypted_blob`
    //    bounds the decrypted size transitively, but we check explicitly.
    {
        use crate::serde_util::BOUNDED_BYTES_MAX;
        if plaintext.len() > BOUNDED_BYTES_MAX {
            return Err(EnvelopeError::EnvelopeTooLarge {
                size: plaintext.len(),
                max: BOUNDED_BYTES_MAX,
            });
        }
    }
    let inner: InnerEnvelope = rmp_serde::from_slice(&plaintext)
        .map_err(|e| EnvelopeError::DeserializationFailed(e.to_string()))?;

    // 3a. Reject unsupported protocol versions early (§13.2.1).
    if inner.version != super::inner::SCP_INNER_ENVELOPE_VERSION {
        return Err(EnvelopeError::UnsupportedVersion {
            version: inner.version,
        });
    }

    // 4. Verify sender_did is a member of the MLS group.
    verify_sender_in_group(group, &inner.sender_did)?;

    // 5. Strip padding to recover original payload.
    let stripped_payload = strip_padding(&inner.payload)?;

    // 6. Verify content integrity: payload_hash == SHA-256(stripped_payload).
    let computed_hash = Sha256::digest(&stripped_payload);
    if computed_hash.as_slice() != &inner.payload_hash[..] {
        return Err(EnvelopeError::ContentIntegrityFailed);
    }

    // 7. Verify inner signature using the sender's public key resolved from MLS.
    let valid = verify_inner_signature(&inner, &sender_public_key)?;
    if !valid {
        return Err(EnvelopeError::InnerSignatureMismatch);
    }

    // 8. Return the verified inner envelope.
    Ok(inner)
}

/// Verifies that the given `sender_did` corresponds to a member of the MLS
/// group by checking the SCP credentials embedded in each member's leaf node.
///
/// # Errors
///
/// Returns [`EnvelopeError::MlsDecryptionFailed`] if the group is destroyed.
/// Returns [`EnvelopeError::UnknownSender`] if no member's credential
/// contains the given DID.
fn verify_sender_in_group(group: &ScpMlsGroup, sender_did: &str) -> Result<(), EnvelopeError> {
    use crate::crypto::mls::credential::ScpCredential;
    use openmls::prelude::BasicCredential;

    let members = group
        .members()
        .map_err(|e| EnvelopeError::MlsDecryptionFailed(e.to_string()))?;

    for member in &members {
        if let Ok(basic_cred) = BasicCredential::try_from(member.credential.clone())
            && let Ok(scp_cred) = ScpCredential::from_bytes(basic_cred.identity())
            && scp_cred.did == sender_did
        {
            return Ok(());
        }
    }

    Err(EnvelopeError::UnknownSender(sender_did.to_owned()))
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

    /// #347: `from_bytes` rejects input exceeding `MAX_ENVELOPE_SIZE` before
    /// invoking the deserializer.
    #[test]
    fn from_bytes_rejects_oversized_input() {
        use crate::serde_util::MAX_ENVELOPE_SIZE;

        let oversized = vec![0u8; MAX_ENVELOPE_SIZE + 1];
        let result = OuterEnvelope::from_bytes(&oversized);
        assert!(result.is_err());

        let err_msg = format!("{result:?}");
        assert!(
            err_msg.contains("EnvelopeTooLarge"),
            "error should be EnvelopeTooLarge, got: {err_msg}"
        );
    }

    /// #347: `from_bytes` accepts input at exactly `MAX_ENVELOPE_SIZE` (the
    /// size check is not off-by-one). The deserialization itself will fail
    /// because the bytes are not valid `MessagePack`, but the size check passes.
    #[test]
    fn from_bytes_accepts_at_limit() {
        use crate::serde_util::MAX_ENVELOPE_SIZE;

        let at_limit = vec![0u8; MAX_ENVELOPE_SIZE];
        let result = OuterEnvelope::from_bytes(&at_limit);
        // Should fail with DeserializationFailed (invalid msgpack), not
        // EnvelopeTooLarge.
        assert!(result.is_err());
        let err_msg = format!("{result:?}");
        assert!(
            err_msg.contains("DeserializationFailed"),
            "should be DeserializationFailed at the limit, got: {err_msg}"
        );
    }
}

/// Integration tests for the high-level seal/open envelope operations.
///
/// These tests exercise the full send -> receive pipeline including MLS
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
    use crate::crypto::sender_keys::generate_sender_key;
    use crate::envelope::inner::{
        InnerEnvelopeParams, MessageType, Provenance, create_inner_envelope,
    };
    use crate::envelope::padding::strip_padding;
    use crate::identity::SigningKeyId;

    #[allow(clippy::unwrap_used)]
    fn test_credential(name: &str) -> ScpCredential {
        ScpCredential::new(
            format!("did:dht:z6Mk{name}"),
            None,
            scp_identity::SigningKeyId::Active,
        )
        .unwrap()
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

    /// Creates an inner envelope signed by the MLS group member's own signing
    /// key, ensuring the signature matches what `open_envelope` will resolve
    /// from the MLS group state.
    ///
    /// The `sender_did` is extracted from the credential in the MLS group,
    /// and the signing key is imported from the MLS signer's private key
    /// into an `InMemoryKeyCustody` instance.
    async fn create_test_inner(
        group: &ScpMlsGroup,
        payload: &[u8],
        provenance: Option<Provenance>,
    ) -> InnerEnvelope {
        // Extract the MLS signer's private key bytes.
        let signer = group.signer.as_ref().expect("group must have a signer");
        let private_key_bytes: [u8; 32] = signer
            .private()
            .try_into()
            .expect("Ed25519 private key must be 32 bytes");

        // Extract the sender DID from the credential.
        let members = group.members().unwrap();
        let own_index = group.own_leaf_index().unwrap();
        let own_member = members
            .iter()
            .find(|m| m.index == own_index)
            .expect("must find own member");
        let basic_cred = BasicCredential::try_from(own_member.credential.clone()).unwrap();
        let scp_cred = ScpCredential::from_bytes(basic_cred.identity()).unwrap();

        // Import the MLS signer's private key into an InMemoryKeyCustody.
        let custody = InMemoryKeyCustody::new();
        let signing_key = custody.import_ed25519_key(&private_key_bytes).await;

        create_inner_envelope(
            &InnerEnvelopeParams {
                version: crate::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: &scp_cred.did,
                epoch: group.epoch().unwrap(),
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload,
                provenance,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap()
    }

    /// Creates an inner envelope signed by a random key (not the MLS group
    /// member's key). Used to test signature mismatch detection.
    async fn create_test_inner_with_random_key(payload: &[u8], sender_did: &str) -> InnerEnvelope {
        let custody = InMemoryKeyCustody::new();
        let signing_key = custody.generate_keypair(KeyType::Ed25519).await.unwrap();

        create_inner_envelope(
            &InnerEnvelopeParams {
                version: crate::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did,
                epoch: 1,
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload,
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap()
    }

    // -----------------------------------------------------------------------
    // seal_envelope tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn seal_envelope_produces_valid_outer_envelope() {
        let (mut alice_group, _bob_group) = setup_mls_groups();
        let inner = create_test_inner(&alice_group, b"hello world", None).await;
        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];

        let outer = seal_envelope(
            &inner,
            &mut alice_group,
            &sender_key,
            &routing_id,
            None,
            3600,
        )
        .unwrap();

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
        let inner = create_test_inner(&alice_group, b"directed message", None).await;
        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];
        let recipient = [0xBB; 32];

        let outer = seal_envelope(
            &inner,
            &mut alice_group,
            &sender_key,
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
        let inner = create_test_inner(&alice_group, b"test", None).await;
        let sender_key = generate_sender_key();

        let result = seal_envelope(
            &inner,
            &mut alice_group,
            &sender_key,
            &[0xAA; 16],
            None,
            3600,
        );
        assert!(result.is_err(), "should reject 16-byte routing_id");
    }

    // -----------------------------------------------------------------------
    // open_envelope tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn seal_then_open_roundtrip_produces_original_content() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();
        let original_payload = b"hello, sealed world!";
        let inner = create_test_inner(&alice_group, original_payload, None).await;
        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];

        // Seal (Alice sends).
        let outer = seal_envelope(
            &inner,
            &mut alice_group,
            &sender_key,
            &routing_id,
            None,
            3600,
        )
        .unwrap();

        // Open (Bob receives) — no sender_public_key needed (SCP-177).
        let recovered = open_envelope(
            &outer,
            &mut bob_group,
            &sender_key,
            &inner.context_id,
            &inner.sender_did,
            inner.epoch,
            inner.sequence,
        )
        .unwrap();

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
        let inner = create_test_inner(
            &alice_group,
            b"payload with provenance",
            Some(provenance.clone()),
        )
        .await;
        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];

        let outer = seal_envelope(
            &inner,
            &mut alice_group,
            &sender_key,
            &routing_id,
            None,
            3600,
        )
        .unwrap();
        let recovered = open_envelope(
            &outer,
            &mut bob_group,
            &sender_key,
            &inner.context_id,
            &inner.sender_did,
            inner.epoch,
            inner.sequence,
        )
        .unwrap();

        assert_eq!(recovered.provenance, Some(provenance));
        assert_eq!(recovered.provenance_hash, inner.provenance_hash);
    }

    #[tokio::test]
    async fn open_envelope_rejects_tampered_encrypted_blob() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();
        let inner = create_test_inner(&alice_group, b"test", None).await;
        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];

        let mut outer = seal_envelope(
            &inner,
            &mut alice_group,
            &sender_key,
            &routing_id,
            None,
            3600,
        )
        .unwrap();

        // Tamper with the encrypted blob (corrupt AEAD tag).
        if let Some(byte) = outer.encrypted_blob.last_mut() {
            *byte ^= 0xFF;
        }

        // Previously OpenMLS panicked on AEAD decryption failure; the
        // catch_unwind guard now converts the panic to an error.
        let result = open_envelope(
            &outer,
            &mut bob_group,
            &sender_key,
            &inner.context_id,
            &inner.sender_did,
            inner.epoch,
            inner.sequence,
        );
        assert!(
            result.is_err(),
            "open_envelope must reject tampered encrypted_blob"
        );

        let err_msg = format!("{result:?}");
        assert!(
            err_msg.contains("MlsDecryptionFailed"),
            "error should be MlsDecryptionFailed, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn open_envelope_rejects_mismatched_payload_hash() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();

        // Extract Alice's MLS signer key to create a properly signed inner.
        let signer = alice_group.signer.as_ref().expect("group must have signer");
        let private_key_bytes: [u8; 32] = signer.private().try_into().unwrap();
        let members = alice_group.members().unwrap();
        let own_index = alice_group.own_leaf_index().unwrap();
        let own_member = members.iter().find(|m| m.index == own_index).unwrap();
        let basic_cred = BasicCredential::try_from(own_member.credential.clone()).unwrap();
        let scp_cred = ScpCredential::from_bytes(basic_cred.identity()).unwrap();

        let custody = InMemoryKeyCustody::new();
        let signing_key = custody.import_ed25519_key(&private_key_bytes).await;

        // Create a legitimate inner envelope.
        let mut inner = create_inner_envelope(
            &InnerEnvelopeParams {
                version: crate::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: &scp_cred.did,
                epoch: alice_group.epoch().unwrap(),
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"original data",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        // Tamper with payload_hash (this also breaks the signature, but
        // content integrity check runs first).
        inner.payload_hash = [0xFF; 32];

        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];
        let outer = seal_envelope(
            &inner,
            &mut alice_group,
            &sender_key,
            &routing_id,
            None,
            3600,
        )
        .unwrap();

        let result = open_envelope(
            &outer,
            &mut bob_group,
            &sender_key,
            &inner.context_id,
            &inner.sender_did,
            inner.epoch,
            inner.sequence,
        );
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

    /// SCP-177: Verifies that `open_envelope` rejects an inner envelope signed
    /// by a key different from the MLS group member's signing key.
    #[tokio::test]
    async fn open_envelope_rejects_wrong_signing_key() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();

        // Create an inner envelope signed by a random key (not Alice's MLS
        // signer). The sender_did matches Alice's credential, but the
        // signature won't match the MLS-resolved public key.
        let members = alice_group.members().unwrap();
        let own_index = alice_group.own_leaf_index().unwrap();
        let own_member = members.iter().find(|m| m.index == own_index).unwrap();
        let basic_cred = BasicCredential::try_from(own_member.credential.clone()).unwrap();
        let scp_cred = ScpCredential::from_bytes(basic_cred.identity()).unwrap();

        let inner = create_test_inner_with_random_key(b"signed by wrong key", &scp_cred.did).await;
        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];

        let outer = seal_envelope(
            &inner,
            &mut alice_group,
            &sender_key,
            &routing_id,
            None,
            3600,
        )
        .unwrap();

        let result = open_envelope(
            &outer,
            &mut bob_group,
            &sender_key,
            &inner.context_id,
            &inner.sender_did,
            inner.epoch,
            inner.sequence,
        );
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
        let inner = create_test_inner(&alice_group, b"replay me", None).await;
        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];

        let outer = seal_envelope(
            &inner,
            &mut alice_group,
            &sender_key,
            &routing_id,
            None,
            3600,
        )
        .unwrap();

        // First open succeeds.
        let _recovered = open_envelope(
            &outer,
            &mut bob_group,
            &sender_key,
            &inner.context_id,
            &inner.sender_did,
            inner.epoch,
            inner.sequence,
        )
        .unwrap();

        // Second open with same ciphertext should fail (MLS generation
        // number replay prevention).
        let replay_result = open_envelope(
            &outer,
            &mut bob_group,
            &sender_key,
            &inner.context_id,
            &inner.sender_did,
            inner.epoch,
            inner.sequence,
        );
        assert!(
            replay_result.is_err(),
            "open_envelope must reject replayed ciphertext"
        );
    }

    #[tokio::test]
    async fn open_envelope_rejects_garbage_encrypted_blob() {
        let (_alice_group, mut bob_group) = setup_mls_groups();
        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];

        let outer =
            create_outer_envelope(&routing_id, None, 3600, vec![0xDE, 0xAD, 0xBE, 0xEF]).unwrap();

        // AAD values are irrelevant: MLS decrypt fails on garbage before
        // the sender key layer is reached.
        let result = open_envelope(
            &outer,
            &mut bob_group,
            &sender_key,
            "ctx-1",
            "did:dht:z6MkDummy",
            0,
            0,
        );
        assert!(
            result.is_err(),
            "open_envelope must reject garbage encrypted_blob"
        );
    }

    #[tokio::test]
    async fn seal_then_open_empty_payload_roundtrip() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();
        let inner = create_test_inner(&alice_group, b"", None).await;
        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];

        let outer = seal_envelope(
            &inner,
            &mut alice_group,
            &sender_key,
            &routing_id,
            None,
            3600,
        )
        .unwrap();
        let recovered = open_envelope(
            &outer,
            &mut bob_group,
            &sender_key,
            &inner.context_id,
            &inner.sender_did,
            inner.epoch,
            inner.sequence,
        )
        .unwrap();

        let stripped = strip_padding(&recovered.payload).unwrap();
        assert!(stripped.is_empty(), "empty payload should roundtrip");

        // Verify payload_hash matches SHA-256 of empty bytes.
        let expected_hash: [u8; 32] = Sha256::digest(b"").into();
        assert_eq!(recovered.payload_hash, expected_hash);
    }

    #[tokio::test]
    async fn seal_then_open_multiple_messages() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();
        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];

        let messages: &[&[u8]] = &[b"first", b"second", b"third"];

        // Seal all messages, keeping the inner envelopes for open_envelope AAD.
        let mut outers = Vec::new();
        let mut inners = Vec::new();
        for msg in messages {
            let inner = create_test_inner(&alice_group, msg, None).await;
            let outer = seal_envelope(
                &inner,
                &mut alice_group,
                &sender_key,
                &routing_id,
                None,
                3600,
            )
            .unwrap();
            outers.push(outer);
            inners.push(inner);
        }

        // Open all messages in order.
        for (i, outer) in outers.iter().enumerate() {
            let ref_inner = &inners[i];
            let recovered = open_envelope(
                outer,
                &mut bob_group,
                &sender_key,
                &ref_inner.context_id,
                &ref_inner.sender_did,
                ref_inner.epoch,
                ref_inner.sequence,
            )
            .unwrap();
            let stripped = strip_padding(&recovered.payload).unwrap();
            assert_eq!(
                stripped, messages[i],
                "message {i} must roundtrip correctly"
            );
        }
    }

    // -----------------------------------------------------------------------
    // SCP-177 specific tests
    // -----------------------------------------------------------------------

    /// SCP-177 AC: envelope from valid group member decrypted with internally
    /// resolved key.
    #[tokio::test]
    async fn open_envelope_resolves_sender_key_from_group() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();
        let inner = create_test_inner(&alice_group, b"internally resolved key test", None).await;
        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];

        let outer = seal_envelope(
            &inner,
            &mut alice_group,
            &sender_key,
            &routing_id,
            None,
            3600,
        )
        .unwrap();

        // open_envelope resolves the sender key internally — no public key arg.
        let recovered = open_envelope(
            &outer,
            &mut bob_group,
            &sender_key,
            &inner.context_id,
            &inner.sender_did,
            inner.epoch,
            inner.sequence,
        )
        .unwrap();
        let stripped = strip_padding(&recovered.payload).unwrap();
        assert_eq!(stripped, b"internally resolved key test");
    }

    /// SCP-177 AC: `sender_id` not in group returns `UnknownSender` error.
    #[tokio::test]
    async fn open_envelope_rejects_unknown_sender_did() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();

        // Create an inner envelope with a DID that is NOT in the group.
        // Sign with Alice's MLS signer key so signature verification would
        // pass, but the DID check should fail first.
        let signer = alice_group.signer.as_ref().expect("group must have signer");
        let private_key_bytes: [u8; 32] = signer.private().try_into().unwrap();

        let custody = InMemoryKeyCustody::new();
        let signing_key = custody.import_ed25519_key(&private_key_bytes).await;

        let inner = create_inner_envelope(
            &InnerEnvelopeParams {
                version: crate::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
                context_id: "ctx-1",
                sender_did: "did:dht:z6MkNOBODY",
                epoch: alice_group.epoch().unwrap(),
                generation: 0,
                sequence: 1,
                timestamp: 1_700_000_000,
                message_type: MessageType::Content,
                payload: b"from unknown sender",
                provenance: None,
                signing_key_id: SigningKeyId::Active,
            },
            &custody,
            &signing_key,
        )
        .await
        .unwrap();

        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];

        let outer = seal_envelope(
            &inner,
            &mut alice_group,
            &sender_key,
            &routing_id,
            None,
            3600,
        )
        .unwrap();

        let result = open_envelope(
            &outer,
            &mut bob_group,
            &sender_key,
            &inner.context_id,
            &inner.sender_did,
            inner.epoch,
            inner.sequence,
        );
        assert!(
            result.is_err(),
            "open_envelope must reject unknown sender DID"
        );

        let err_msg = format!("{result:?}");
        assert!(
            err_msg.contains("UnknownSender"),
            "error should be UnknownSender, got: {err_msg}"
        );
    }

    // -----------------------------------------------------------------------
    // sender key layer tests
    // -----------------------------------------------------------------------

    /// Confirms that ciphertext produced by `seal_envelope` cannot be opened
    /// without the correct sender key, even if MLS decryption succeeds.
    /// Using the wrong sender key must yield `SenderKeyDecryptionFailed`.
    #[tokio::test]
    async fn open_envelope_rejects_wrong_sender_key() {
        let (mut alice_group, mut bob_group) = setup_mls_groups();
        let inner = create_test_inner(&alice_group, b"sender key protected", None).await;
        let correct_sender_key = generate_sender_key();
        let wrong_sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];

        // Seal with the correct sender key.
        let outer = seal_envelope(
            &inner,
            &mut alice_group,
            &correct_sender_key,
            &routing_id,
            None,
            3600,
        )
        .unwrap();

        // Open with a different sender key — MLS decryption succeeds, but
        // sender key decryption must fail.
        let result = open_envelope(
            &outer,
            &mut bob_group,
            &wrong_sender_key,
            &inner.context_id,
            &inner.sender_did,
            inner.epoch,
            inner.sequence,
        );
        assert!(
            result.is_err(),
            "open_envelope must reject wrong sender key"
        );

        let err_msg = format!("{result:?}");
        assert!(
            err_msg.contains("SenderKeyDecryptionFailed"),
            "error should be SenderKeyDecryptionFailed, got: {err_msg}"
        );
    }

    /// Confirms that tampered sender-key ciphertext is rejected with an
    /// authentication failure before inner envelope deserialization is
    /// attempted. We manually build the pipeline to inject tampering at
    /// the sender-key-ciphertext layer (after sender key encrypt, before
    /// MLS encrypt).
    #[tokio::test]
    async fn open_envelope_rejects_tampered_sender_key_ciphertext() {
        use crate::crypto::mls::encrypt::{
            encrypt as mls_encrypt, serialize_ciphertext as mls_serialize,
        };
        use crate::crypto::sender_keys::encrypt::encrypt_sender_layer;

        let (mut alice_group, mut bob_group) = setup_mls_groups();
        let inner = create_test_inner(&alice_group, b"tamper target", None).await;
        let sender_key = generate_sender_key();
        let routing_id = [0xAA; 32];

        // Step 1: Serialize inner envelope.
        let serialized = rmp_serde::to_vec_named(&inner).unwrap();

        // Step 2: Encrypt with sender key.
        let mut sender_encrypted = encrypt_sender_layer(
            &sender_key,
            &serialized,
            &inner.context_id,
            &inner.sender_did,
            inner.epoch,
            inner.sequence,
        )
        .unwrap();

        // Step 3: Tamper with the sender-key ciphertext (flip a byte in
        // the encrypted portion, after the 12-byte nonce).
        let tamper_index = 12 + 1; // nonce is 12 bytes, tamper first encrypted byte
        sender_encrypted[tamper_index] ^= 0xFF;

        // Step 4: MLS-encrypt the tampered bytes (MLS doesn't know they're
        // tampered — it just encrypts whatever it receives).
        let mls_message = mls_encrypt(&mut alice_group, &sender_encrypted).unwrap();
        let encrypted_blob = mls_serialize(&mls_message).unwrap();

        // Step 5: Wrap in outer envelope.
        let outer = create_outer_envelope(&routing_id, None, 3600, encrypted_blob).unwrap();

        // Step 6: Try to open — MLS decryption succeeds, but sender key
        // authentication tag verification must fail.
        let result = open_envelope(
            &outer,
            &mut bob_group,
            &sender_key,
            &inner.context_id,
            &inner.sender_did,
            inner.epoch,
            inner.sequence,
        );
        assert!(
            result.is_err(),
            "open_envelope must reject tampered sender-key ciphertext"
        );

        let err_msg = format!("{result:?}");
        assert!(
            err_msg.contains("SenderKeyDecryptionFailed"),
            "error should be SenderKeyDecryptionFailed (auth tag failure), got: {err_msg}"
        );

        // Verify the error message traces back to AuthenticationFailed.
        assert!(
            err_msg.contains("authentication tag verification failed"),
            "error should mention authentication tag failure, got: {err_msg}"
        );
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
                    let inner = create_test_inner(&alice_group, &payload, None).await;
                    let sender_key = generate_sender_key();
                    let routing_id = [0xAA; 32];

                    let outer = seal_envelope(
                        &inner,
                        &mut alice_group,
                        &sender_key,
                        &routing_id,
                        None,
                        3600,
                    ).unwrap();

                    let recovered = open_envelope(
                        &outer,
                        &mut bob_group,
                        &sender_key,
                        &inner.context_id,
                        &inner.sender_did,
                        inner.epoch,
                        inner.sequence,
                    ).unwrap();

                    let stripped = strip_padding(&recovered.payload).unwrap();
                    prop_assert_eq!(stripped, payload);

                    Ok(())
                })?;
            }
        }
    }
}
