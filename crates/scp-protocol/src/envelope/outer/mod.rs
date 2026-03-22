//! Outer envelope construction, serialization, and high-level seal/open
//! operations.
//!
//! The outer envelope is the wire format visible to relays and the network.
//! It is deliberately minimal to limit metadata exposure: relays see only a
//! pseudonym-based `routing_id`, an optional `recipient_hint`, a `blob_ttl`,
//! and an opaque `encrypted_blob`.
//!
//! The async `ops` module (`seal_envelope`, `open_envelope`) stays in scp-runtime.
//!
//! See ADR-002 in `.docs/adrs/phase-1.md` for the full outer envelope design.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::EnvelopeError;

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
