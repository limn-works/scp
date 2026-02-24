//! Outer envelope construction and serialization.
//!
//! The outer envelope is the wire format visible to relays and the network.
//! It is deliberately minimal to limit metadata exposure: relays see only a
//! pseudonym-based `routing_id`, an optional `recipient_hint`, a `blob_ttl`,
//! and an opaque `encrypted_blob`.
//!
//! See ADR-002 in `.docs/adrs/phase-1.md` for the full outer envelope design.

use serde::{Deserialize, Serialize};

use super::EnvelopeError;

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
