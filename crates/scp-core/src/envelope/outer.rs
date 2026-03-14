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

use std::collections::HashMap;

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

/// The unauthenticated outer envelope used for relay routing.
///
/// Wraps an MLS-encrypted ciphertext blob with routing metadata visible to
/// untrusted relays. Fields are unsigned — authenticity is provided by MLS
/// at the inner layer (spec §13.2.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    ///
    /// **Interaction with `#[serde(flatten)]` on `extensions`:** When
    /// `flatten` is present, serde buffers all map entries before dispatching
    /// to field deserializers. This means `serde_bounded_bytes` fires *after*
    /// the full input has been buffered into memory. The pre-deserialization
    /// `MAX_ENVELOPE_SIZE` check in [`OuterEnvelope::from_bytes`] is the
    /// primary defense against oversized inputs; `serde_bounded_bytes` acts
    /// as defense-in-depth for the individual field.
    #[serde(with = "crate::serde_util::serde_bounded_bytes")]
    pub encrypted_blob: Vec<u8>,

    /// Forward-compatibility extensions — unknown fields from future protocol
    /// versions are preserved here for forward-compatible roundtripping
    /// (§13.5.1). Intermediaries (relays, bridges) that deserialize and
    /// re-serialize outer envelopes MUST NOT strip unrecognized fields.
    ///
    /// Uses `rmpv::Value` (not `serde_json::Value`) to preserve `MessagePack`
    /// type fidelity. A `MsgPack` Binary field roundtrips as Binary; with
    /// `serde_json::Value` it would degrade to an Array of numbers — silent
    /// data corruption.
    ///
    /// **Security note:** Extensions carry no authenticity guarantee. The outer
    /// envelope is unsigned, and these fields have no integrity protection
    /// beyond the MLS encryption of the inner envelope. Do not use extension
    /// values for security-sensitive decisions.
    #[serde(flatten)]
    pub extensions: HashMap<String, rmpv::Value>,

    /// The result of version compatibility checking, recorded by
    /// [`OuterEnvelope::from_bytes`] so callers can programmatically detect
    /// degraded mode without re-checking the version field.
    ///
    /// `None` when the envelope was constructed locally (e.g., via
    /// [`create_outer_envelope`]) rather than deserialized from the wire.
    ///
    /// This field is not serialized — it is a local annotation, not part of
    /// the wire format.
    #[serde(skip)]
    pub version_compatibility: Option<super::VersionCompatibility>,
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
        extensions: HashMap::new(),
        version_compatibility: None,
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
    /// `encrypted_blob`). Unknown extension fields are preserved
    /// unconditionally per spec §13.5.1 (relays MUST NOT strip unknown
    /// fields from outer envelopes).
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
        let mut envelope: Self = rmp_serde::from_slice(bytes)
            .map_err(|e| EnvelopeError::DeserializationFailed(e.to_string()))?;

        // §13.5: accept same-major versions, reject different majors.
        let compat = super::check_version_compatibility(envelope.version)?;
        if let super::VersionCompatibility::DegradedMode {
            local_minor,
            remote_minor,
        } = compat
        {
            tracing::warn!(
                wire_version = format_args!("{:#06x}", envelope.version),
                local_version = format_args!("{:#06x}", super::SCP_PROTOCOL_VERSION),
                local_minor,
                remote_minor,
                "outer envelope minor version mismatch — operating in degraded mode (§13.6)"
            );
        }

        // Record the compatibility result so callers can detect degraded mode
        // programmatically without re-checking (#628 F4).
        envelope.version_compatibility = Some(compat);

        Ok(envelope)
    }

    /// Validates that this outer envelope's version field is compatible (§13.5).
    ///
    /// Accepts envelopes with the same major version. When minor versions
    /// differ, the implementation operates in degraded mode (§13.6) and a
    /// `tracing::warn!` is emitted.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::UnsupportedVersion`] if the major version
    /// differs from this implementation's major version.
    pub fn validate_version(&self) -> Result<super::VersionCompatibility, EnvelopeError> {
        let compat = super::check_version_compatibility(self.version)?;
        if let super::VersionCompatibility::DegradedMode {
            local_minor,
            remote_minor,
        } = compat
        {
            tracing::warn!(
                wire_version = format_args!("{:#06x}", self.version),
                local_version = format_args!("{:#06x}", super::SCP_PROTOCOL_VERSION),
                local_minor,
                remote_minor,
                "outer envelope minor version mismatch — operating in degraded mode (§13.6)"
            );
        }
        Ok(compat)
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

    // 3. Deserialize inner envelope via `from_bytes` (#347, #863).
    //    `from_bytes` applies a pre-deserialization size check against
    //    `MAX_ENVELOPE_SIZE` before invoking the deserializer, preventing
    //    `serde`'s `#[serde(flatten)]` buffering from allocating memory for
    //    oversized inputs. The outer envelope's `BOUNDED_BYTES_MAX` limit on
    //    `encrypted_blob` bounds the decrypted size transitively;
    //    `from_bytes` acts as defense in depth.
    let inner = InnerEnvelope::from_bytes(&plaintext)?;

    // 3a. Reject incompatible major versions early (§13.5).
    //     Same-major envelopes with different minor versions proceed in
    //     degraded mode.
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
            context_id = %inner.context_id,
            sender_did = %inner.sender_did,
            "inner envelope minor version mismatch — operating in degraded mode (§13.6)"
        );
    }

    // 4. Verify sender_did is a member of the MLS group.
    verify_sender_in_group(group, &inner.sender_did)?;

    // 5. Strip padding to recover original payload.
    let stripped_payload = strip_padding(&inner.payload)?;

    // 6. Verify content integrity: payload_hash == SHA-256(stripped_payload).
    //    Constant-time comparison to prevent timing side-channels.
    let computed_hash = Sha256::digest(&stripped_payload);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(
        computed_hash.as_slice(),
        &inner.payload_hash[..],
    )) {
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

    // -------------------------------------------------------------------
    // Forward compatibility: unknown fields preserved (§13.5.1, #593, #919)
    // -------------------------------------------------------------------

    /// Injects extra string-keyed string-valued fields into a `MessagePack`
    /// named map, simulating a newer protocol version's extra fields.
    fn inject_msgpack_str_fields(original: &[u8], extras: &[(&str, &str)]) -> Vec<u8> {
        let first = original[0];
        let (old_count, body_offset) = if first & 0xF0 == 0x80 {
            (u32::from(first & 0x0F), 1)
        } else if first == 0xDE {
            let count = u32::from(u16::from_be_bytes([original[1], original[2]]));
            (count, 3)
        } else if first == 0xDF {
            let count = u32::from_be_bytes([original[1], original[2], original[3], original[4]]);
            (count, 5)
        } else {
            panic!("expected msgpack map header, got 0x{first:02X}");
        };

        let new_count = old_count + u32::try_from(extras.len()).unwrap();
        let mut result = Vec::with_capacity(original.len() + extras.len() * 64);

        // Write new map header.
        if new_count <= 15 {
            result.push(0x80 | u8::try_from(new_count).unwrap());
        } else if new_count <= 0xFFFF {
            result.push(0xDE);
            result.extend_from_slice(&u16::try_from(new_count).unwrap().to_be_bytes());
        } else {
            result.push(0xDF);
            result.extend_from_slice(&new_count.to_be_bytes());
        }

        // Copy existing map body.
        result.extend_from_slice(&original[body_offset..]);

        // Append extra key-value pairs as fixstr.
        for (k, v) in extras {
            // Encode key.
            let kb = k.as_bytes();
            if kb.len() <= 31 {
                result.push(0xA0 | u8::try_from(kb.len()).unwrap());
            } else {
                result.push(0xD9);
                result.push(u8::try_from(kb.len()).unwrap());
            }
            result.extend_from_slice(kb);
            // Encode value.
            let vb = v.as_bytes();
            if vb.len() <= 31 {
                result.push(0xA0 | u8::try_from(vb.len()).unwrap());
            } else {
                result.push(0xD9);
                result.push(u8::try_from(vb.len()).unwrap());
            }
            result.extend_from_slice(vb);
        }
        result
    }

    /// Injects a single Binary-typed extension field into a `MessagePack`
    /// named map. This simulates a future protocol version adding a field
    /// whose wire type is `MsgPack` Binary (0xC4/0xC5/0xC6).
    fn inject_msgpack_binary_field(original: &[u8], key: &str, data: &[u8]) -> Vec<u8> {
        let first = original[0];
        let (old_count, body_offset) = if first & 0xF0 == 0x80 {
            (u32::from(first & 0x0F), 1)
        } else if first == 0xDE {
            let count = u32::from(u16::from_be_bytes([original[1], original[2]]));
            (count, 3)
        } else if first == 0xDF {
            let count = u32::from_be_bytes([original[1], original[2], original[3], original[4]]);
            (count, 5)
        } else {
            panic!("expected msgpack map header, got 0x{first:02X}");
        };

        let new_count = old_count + 1;
        let mut result = Vec::with_capacity(original.len() + key.len() + data.len() + 16);

        if new_count <= 15 {
            result.push(0x80 | u8::try_from(new_count).unwrap());
        } else if new_count <= 0xFFFF {
            result.push(0xDE);
            result.extend_from_slice(&u16::try_from(new_count).unwrap().to_be_bytes());
        } else {
            result.push(0xDF);
            result.extend_from_slice(&new_count.to_be_bytes());
        }

        result.extend_from_slice(&original[body_offset..]);

        // Key as fixstr / str8.
        let kb = key.as_bytes();
        if kb.len() <= 31 {
            result.push(0xA0 | u8::try_from(kb.len()).unwrap());
        } else {
            result.push(0xD9);
            result.push(u8::try_from(kb.len()).unwrap());
        }
        result.extend_from_slice(kb);

        // Value as bin8/bin16/bin32.
        let len = data.len();
        if len <= 0xFF {
            result.push(0xC4);
            result.push(u8::try_from(len).unwrap());
        } else if len <= 0xFFFF {
            result.push(0xC5);
            result.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        } else {
            result.push(0xC6);
            result.extend_from_slice(&u32::try_from(len).unwrap().to_be_bytes());
        }
        result.extend_from_slice(data);

        result
    }

    #[test]
    fn outer_envelope_ignores_unknown_fields() {
        let envelope = create_outer_envelope(&[0xAA; 32], None, 3600, vec![0x01]).unwrap();
        let bytes = envelope.to_bytes().unwrap();
        let with_extra = inject_msgpack_str_fields(&bytes, &[("future_protocol_field", "v2-data")]);

        let result = OuterEnvelope::from_bytes(&with_extra);
        assert!(
            result.is_ok(),
            "wire-format types must accept unknown fields per §13.5.1: {:?}",
            result.unwrap_err()
        );
        let decoded = result.unwrap();
        assert_eq!(decoded.routing_id, envelope.routing_id);
        assert_eq!(decoded.blob_ttl, envelope.blob_ttl);
    }

    /// §13.5.1: `OuterEnvelope` MUST preserve unknown fields so intermediaries
    /// (relays, bridges) don't strip fields from newer protocol versions.
    #[test]
    fn outer_envelope_preserves_unknown_fields_roundtrip() {
        let envelope =
            create_outer_envelope(&[0xBB; 32], Some(&[0xCC; 32]), 7200, vec![0xDE, 0xAD]).unwrap();
        let bytes = envelope.to_bytes().unwrap();
        let with_extra = inject_msgpack_str_fields(&bytes, &[("v2_routing_priority", "high")]);

        // Deserialize — the unknown field should land in `extensions`.
        let decoded = OuterEnvelope::from_bytes(&with_extra).unwrap();
        assert_eq!(decoded.routing_id, envelope.routing_id);
        assert_eq!(decoded.blob_ttl, 7200);
        assert_eq!(decoded.encrypted_blob, vec![0xDE, 0xAD]);

        // Verify the injected field survived in extensions.
        assert!(
            decoded.extensions.contains_key("v2_routing_priority"),
            "unknown field must be preserved in extensions"
        );
        assert_eq!(
            decoded.extensions["v2_routing_priority"],
            rmpv::Value::String("high".into()),
        );

        // Re-serialize and re-deserialize — extensions must survive.
        let re_bytes = decoded.to_bytes().unwrap();
        let re_decoded = OuterEnvelope::from_bytes(&re_bytes).unwrap();
        assert!(
            re_decoded.extensions.contains_key("v2_routing_priority"),
            "unknown field must survive serialize → deserialize → serialize roundtrip"
        );
    }

    /// Full roundtrip — serialize → inject unknown → deserialize → compare.
    #[test]
    fn outer_envelope_roundtrip_with_unknown_field() {
        let original =
            create_outer_envelope(&[0xAA; 32], Some(&[0xDD; 32]), 3600, vec![0x42; 16]).unwrap();
        let bytes = original.to_bytes().unwrap();
        let with_extra = inject_msgpack_str_fields(&bytes, &[("future_version_hint", "scp/2.0")]);

        let decoded = OuterEnvelope::from_bytes(&with_extra).unwrap();

        // Key fields match the original.
        assert_eq!(decoded.version, original.version);
        assert_eq!(decoded.routing_id, original.routing_id);
        assert_eq!(decoded.recipient_hint, original.recipient_hint);
        assert_eq!(decoded.blob_ttl, original.blob_ttl);
        assert_eq!(decoded.encrypted_blob, original.encrypted_blob);

        // Unknown field preserved.
        assert_eq!(
            decoded.extensions.get("future_version_hint"),
            Some(&rmpv::Value::String("scp/2.0".into())),
        );
    }

    /// #593-F1: Extensions must survive a `MessagePack` roundtrip — the actual
    /// wire format. This test proves that `#[serde(flatten)]` extensions with
    /// `rmpv::Value` survive `rmp_serde` encode → decode.
    #[test]
    fn outer_envelope_extensions_survive_msgpack_roundtrip() {
        // A wrapper struct that has all OuterEnvelope fields plus one extra.
        // Serializing this to MessagePack simulates a newer protocol version
        // adding a field that older versions don't know about.
        #[derive(serde::Serialize)]
        struct ExtendedOuterEnvelope {
            version: u16,
            #[serde(with = "serde_bytes")]
            routing_id: Vec<u8>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            recipient_hint: Option<Vec<u8>>,
            blob_ttl: u32,
            #[serde(with = "serde_bytes")]
            encrypted_blob: Vec<u8>,
            /// Field unknown to the current `OuterEnvelope` definition.
            v2_routing_priority: rmpv::Value,
        }

        let extended = ExtendedOuterEnvelope {
            version: SCP_OUTER_ENVELOPE_VERSION,
            routing_id: vec![0xBB; 32],
            recipient_hint: Some(vec![0xCC; 32]),
            blob_ttl: 7200,
            encrypted_blob: vec![0xDE, 0xAD],
            v2_routing_priority: rmpv::Value::String("high".into()),
        };

        // Step 1: Serialize the extended struct to MessagePack (named fields).
        let msgpack_bytes = rmp_serde::to_vec_named(&extended).unwrap();

        // Step 2: Deserialize as the standard OuterEnvelope.
        let decoded: OuterEnvelope = rmp_serde::from_slice(&msgpack_bytes).unwrap();

        // Step 3: Known fields must be correct.
        assert_eq!(decoded.version, SCP_OUTER_ENVELOPE_VERSION);
        assert_eq!(decoded.routing_id, vec![0xBB; 32]);
        assert_eq!(
            decoded.recipient_hint.as_deref(),
            Some(vec![0xCC; 32].as_slice())
        );
        assert_eq!(decoded.blob_ttl, 7200);
        assert_eq!(decoded.encrypted_blob, vec![0xDE, 0xAD]);

        // Step 4: The unknown field must survive in extensions.
        assert!(
            decoded.extensions.contains_key("v2_routing_priority"),
            "unknown field must be preserved in extensions after msgpack roundtrip, got: {:?}",
            decoded.extensions
        );
        assert_eq!(
            decoded.extensions["v2_routing_priority"],
            rmpv::Value::String("high".into()),
        );

        // Step 5: Re-serialize and re-deserialize — the extension must persist.
        let re_encoded = rmp_serde::to_vec_named(&decoded).unwrap();
        let re_decoded: OuterEnvelope = rmp_serde::from_slice(&re_encoded).unwrap();
        assert!(
            re_decoded.extensions.contains_key("v2_routing_priority"),
            "unknown field must survive msgpack serialize → deserialize → serialize → deserialize"
        );
    }

    /// §13.5.1: `from_bytes` preserves many extension keys unconditionally.
    /// Relays MUST NOT strip unknown fields from outer envelopes.
    #[test]
    fn from_bytes_preserves_many_extension_keys() {
        let envelope = create_outer_envelope(&[0xAA; 32], None, 3600, vec![0x01]).unwrap();
        // Inject extensions directly into the struct then roundtrip via msgpack.
        let mut extended = envelope;
        for i in 0..64 {
            extended
                .extensions
                .insert(format!("ext_key_{i}"), rmpv::Value::Integer(i.into()));
        }
        assert_eq!(extended.extensions.len(), 64);
        let bytes = extended.to_bytes().unwrap();

        let result = OuterEnvelope::from_bytes(&bytes);
        assert!(
            result.is_ok(),
            "should preserve all extension keys per §13.5.1: {:?}",
            result.unwrap_err()
        );
        let recovered = result.unwrap();
        assert_eq!(
            recovered.extensions.len(),
            64,
            "all 64 extension keys must survive roundtrip"
        );
    }

    /// §13.5.1 / #919: A `MessagePack` Binary extension field MUST roundtrip
    /// as Binary, not degrade to Array. This is the key motivation for using
    /// `rmpv::Value` instead of `serde_json::Value` in `OuterEnvelope`
    /// extensions (matching the `InnerEnvelope` fix from #863).
    #[test]
    fn binary_extension_survives_roundtrip_as_binary() {
        let envelope = create_outer_envelope(&[0xAA; 32], None, 3600, vec![0x01]).unwrap();
        let bytes = envelope.to_bytes().unwrap();

        // Inject a Binary-typed extension field at the raw msgpack level.
        // This simulates a future protocol version that adds a binary field.
        let binary_data: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let with_binary = inject_msgpack_binary_field(&bytes, "future_binary_field", binary_data);

        // First deserialization: binary must land in extensions as Binary.
        let decoded = OuterEnvelope::from_bytes(&with_binary)
            .expect("OuterEnvelope must accept binary extension fields");

        let ext = decoded
            .extensions
            .get("future_binary_field")
            .expect("extensions must contain future_binary_field");

        // CRITICAL: The value must be Binary, not Array.
        assert!(
            matches!(ext, rmpv::Value::Binary(_)),
            "binary extension field must be rmpv::Value::Binary, got: {ext:?}"
        );
        assert_eq!(
            ext,
            &rmpv::Value::Binary(binary_data.to_vec()),
            "binary content must be preserved exactly"
        );

        // Roundtrip: re-serialize and re-deserialize — must stay Binary.
        let re_bytes = decoded.to_bytes().unwrap();
        let re_decoded = OuterEnvelope::from_bytes(&re_bytes).unwrap();
        let re_ext = re_decoded
            .extensions
            .get("future_binary_field")
            .expect("binary extension must survive roundtrip");
        assert!(
            matches!(re_ext, rmpv::Value::Binary(_)),
            "binary extension must remain Binary after roundtrip, got: {re_ext:?}"
        );
        assert_eq!(
            re_ext,
            &rmpv::Value::Binary(binary_data.to_vec()),
            "binary content must survive roundtrip exactly"
        );
    }

    /// #593-F4: `serde_bounded_bytes` still fires on `encrypted_blob` even
    /// when `#[serde(flatten)]` on `extensions` causes serde to buffer all
    /// fields. Crafts a `MessagePack` map with `encrypted_blob` exceeding
    /// `BOUNDED_BYTES_MAX` but within `MAX_ENVELOPE_SIZE`, verifying that
    /// the per-field guard still rejects it.
    #[test]
    fn serde_bounded_bytes_fires_with_flatten_present() {
        use crate::serde_util::{BOUNDED_BYTES_MAX, MAX_ENVELOPE_SIZE};

        // Construct a valid msgpack map with the oversized blob.
        // We use a helper struct to ensure correct serde_bytes encoding.
        #[derive(serde::Serialize)]
        struct OversizedEnvelope {
            version: u16,
            #[serde(with = "serde_bytes")]
            routing_id: Vec<u8>,
            blob_ttl: u32,
            #[serde(with = "serde_bytes")]
            encrypted_blob: Vec<u8>,
        }

        // Build a struct with an oversized encrypted_blob that's still
        // within MAX_ENVELOPE_SIZE. BOUNDED_BYTES_MAX = 512 KiB,
        // MAX_ENVELOPE_SIZE = 576 KiB. Use BOUNDED_BYTES_MAX + 1 bytes
        // for the blob.
        let oversized_blob = vec![0xAAu8; BOUNDED_BYTES_MAX + 1];

        let crafted = OversizedEnvelope {
            version: SCP_OUTER_ENVELOPE_VERSION,
            routing_id: vec![0xBB; 32],
            blob_ttl: 3600,
            encrypted_blob: oversized_blob,
        };
        let bytes = rmp_serde::to_vec_named(&crafted).unwrap();

        // Sanity: total size is within MAX_ENVELOPE_SIZE (the oversized blob
        // is just over 512 KiB, but the total is under 576 KiB).
        assert!(
            bytes.len() <= MAX_ENVELOPE_SIZE,
            "test expects total size within MAX_ENVELOPE_SIZE, got {}",
            bytes.len()
        );

        // from_bytes should fail because serde_bounded_bytes rejects the
        // oversized encrypted_blob.
        let result = OuterEnvelope::from_bytes(&bytes);
        assert!(
            result.is_err(),
            "serde_bounded_bytes should reject blob > BOUNDED_BYTES_MAX even with flatten"
        );
        let err_msg = format!("{result:?}");
        assert!(
            err_msg.contains("DeserializationFailed"),
            "should be DeserializationFailed from serde_bounded_bytes, got: {err_msg}"
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
