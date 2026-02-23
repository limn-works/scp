//! Outer envelope — the wire format visible to relays and the network.
//!
//! Contains only routing information and an opaque encrypted blob.
//! Relays route by `routing_id`, store for `blob_ttl`, and delete.
//! They learn nothing about sender, context, or content. See ADR-002.

use serde::{Deserialize, Serialize};

/// The outer envelope — what relays and the network see.
///
/// Deliberately minimal to limit metadata exposure. The `routing_id` is a
/// per-context pseudonym derived via HMAC-SHA256 (Decision 7). The
/// `encrypted_blob` is the MLS-encrypted inner envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OuterEnvelope {
    /// Per-context pseudonym for routing, derived via HMAC-SHA256.
    ///
    /// Same identity + same context = same pseudonym.
    /// Different context = different, unlinkable pseudonym.
    pub routing_id: [u8; 32],
    /// Optional recipient pseudonym for directed messages.
    ///
    /// When `Some`, indicates a directed message to a specific recipient.
    /// When `None`, the message is broadcast to all subscribers.
    pub recipient_hint: Option<[u8; 32]>,
    /// Time-to-live in seconds — how long the relay should store the blob
    /// before deletion.
    pub blob_ttl: u32,
    /// The MLS-encrypted inner envelope (opaque to relays).
    pub encrypted_blob: Vec<u8>,
}

/// Constructs a new [`OuterEnvelope`] from its constituent parts.
///
/// This is a simple constructor that assembles the minimal outer envelope.
/// No validation is performed on the blob contents (the relay treats it
/// as opaque). See ADR-002 acceptance criterion 3.
#[must_use]
pub const fn create_outer_envelope(
    routing_id: [u8; 32],
    recipient_hint: Option<[u8; 32]>,
    blob_ttl: u32,
    encrypted_blob: Vec<u8>,
) -> OuterEnvelope {
    OuterEnvelope {
        routing_id,
        recipient_hint,
        blob_ttl,
        encrypted_blob,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn outer_envelope_serializes_to_and_from_msgpack() {
        let envelope =
            create_outer_envelope([0x01; 32], Some([0x02; 32]), 3600, vec![0xaa, 0xbb, 0xcc]);

        let packed = rmp_serde::to_vec(&envelope).expect("serialization should succeed in test");
        let unpacked: OuterEnvelope =
            rmp_serde::from_slice(&packed).expect("deserialization should succeed in test");

        assert_eq!(envelope, unpacked);
    }

    #[test]
    fn outer_envelope_without_recipient_hint_roundtrips() {
        let envelope = create_outer_envelope([0xff; 32], None, 86400, vec![1, 2, 3, 4, 5]);

        let packed = rmp_serde::to_vec(&envelope).expect("serialization should succeed in test");
        let unpacked: OuterEnvelope =
            rmp_serde::from_slice(&packed).expect("deserialization should succeed in test");

        assert_eq!(envelope, unpacked);
    }

    #[test]
    fn create_outer_envelope_sets_all_fields() {
        let routing_id = [0x42; 32];
        let hint = [0x99; 32];
        let blob = vec![10, 20, 30];

        let env = create_outer_envelope(routing_id, Some(hint), 7200, blob.clone());

        assert_eq!(env.routing_id, routing_id);
        assert_eq!(env.recipient_hint, Some(hint));
        assert_eq!(env.blob_ttl, 7200);
        assert_eq!(env.encrypted_blob, blob);
    }
}
