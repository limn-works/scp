//! Wire-format message types for the SCP native relay protocol.
//!
//! Serialization uses `MessagePack` (via `rmp-serde`) over `WebSocket` binary
//! frames. Every message is a `MessagePack` map with a required `op` field
//! (string) plus operation-specific fields. See ADR-004 for the full wire
//! format specification.
//!
//! # Serialization
//!
//! Use [`serialize_client_message`] and [`serialize_relay_message`] to produce
//! `MessagePack` bytes, and [`deserialize_client_message`] /
//! [`deserialize_relay_message`] to parse them.
//!
//! Binary fields (`routing_id`, `blob_id`, `recipient_hint`) are exactly 32
//! bytes and serialized as `MessagePack` `bin` format.

use serde::{Deserialize, Serialize};

use super::error::ProtocolError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum blob size in bytes (256 KB).
pub const MAX_BLOB_SIZE: usize = 262_144;

/// Minimum blob TTL in seconds.
pub const MIN_BLOB_TTL: u32 = 1;

/// Maximum blob TTL in seconds (7 days).
pub const MAX_BLOB_TTL: u32 = 604_800;

/// Maximum length of a correlation `ref` string in bytes.
pub const MAX_REF_LENGTH: usize = 64;

/// Byte length for binary identifiers (`routing_id`, `blob_id`,
/// `recipient_hint`).
pub const BINARY_ID_LENGTH: usize = 32;

// ---------------------------------------------------------------------------
// Client-to-Relay messages
// ---------------------------------------------------------------------------

/// A message sent from a client to the relay.
///
/// Each variant corresponds to one of the six client operations defined in
/// ADR-004, plus `Ping` for keepalive. The enum is internally tagged on the
/// `op` field for `MessagePack` serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum ClientMessage {
    /// Publish an opaque blob to the relay, associated with a `routing_id`.
    ///
    /// The relay stores the blob for `blob_ttl` seconds and delivers it to
    /// active subscribers of the given `routing_id`.
    #[serde(rename = "PUBLISH")]
    Publish {
        /// Client-assigned correlation ID (max 64 bytes, echoed in response).
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// Per-context pseudonym for routing (exactly 32 bytes).
        routing_id: [u8; 32],

        /// Optional recipient pseudonym for directed delivery (exactly 32
        /// bytes).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recipient_hint: Option<[u8; 32]>,

        /// Time-to-live in seconds (1..=604 800).
        blob_ttl: u32,

        /// The opaque encrypted blob (1..=262 144 bytes).
        blob: Vec<u8>,
    },

    /// Subscribe to blobs for a `routing_id`.
    ///
    /// The relay pushes new blobs via `WebSocket` and optionally backfills
    /// stored blobs newer than `since`.
    #[serde(rename = "SUBSCRIBE")]
    Subscribe {
        /// Client-assigned correlation ID.
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// Per-context pseudonym to subscribe to (exactly 32 bytes).
        routing_id: [u8; 32],

        /// Optional Unix timestamp; backfill stored blobs newer than this.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since: Option<u64>,
    },

    /// Unsubscribe from a `routing_id` on this connection.
    #[serde(rename = "UNSUBSCRIBE")]
    Unsubscribe {
        /// Client-assigned correlation ID.
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// Per-context pseudonym to unsubscribe from (exactly 32 bytes).
        routing_id: [u8; 32],
    },

    /// One-shot query for stored blobs matching a `routing_id`.
    ///
    /// Does not create a subscription. The relay responds with a stream of
    /// `BLOB` messages followed by an `EVENT` with `type = "query_complete"`.
    #[serde(rename = "QUERY")]
    Query {
        /// Client-assigned correlation ID.
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// Per-context pseudonym to query (exactly 32 bytes).
        routing_id: [u8; 32],

        /// Optional Unix timestamp filter.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since: Option<u64>,

        /// Maximum number of results (default 100, max 1 000).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
    },

    /// Request deletion of a blob by its `blob_id` (best-effort).
    #[serde(rename = "DELETE")]
    Delete {
        /// Client-assigned correlation ID.
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// SHA-256 hash of the blob (exactly 32 bytes).
        blob_id: [u8; 32],
    },

    /// Delivery acknowledgement (fire-and-forget, no response).
    #[serde(rename = "ACK")]
    Ack {
        /// SHA-256 hash of the acknowledged blob (exactly 32 bytes).
        blob_id: [u8; 32],
    },

    /// Keepalive ping. The relay responds with [`RelayMessage::Pong`].
    #[serde(rename = "PING")]
    Ping {
        /// Client timestamp (typically Unix milliseconds).
        ts: u64,
    },
}

// ---------------------------------------------------------------------------
// Relay-to-Client messages
// ---------------------------------------------------------------------------

/// A message sent from the relay to a client.
///
/// Each variant corresponds to one of the five relay operations defined in
/// ADR-004. The enum is internally tagged on the `op` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum RelayMessage {
    /// Success response. `blob_id` is present only for `PUBLISH` responses.
    #[serde(rename = "OK")]
    Ok {
        /// Echoed correlation ID from the client request.
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// The `SHA-256(blob)` identifier, present only for PUBLISH
        /// responses.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blob_id: Option<[u8; 32]>,
    },

    /// Error response with a numeric code and human-readable message.
    ///
    /// `msg` is for logging; clients MUST NOT parse it for control flow.
    /// See [`super::error`] for error code constants.
    #[serde(rename = "ERR")]
    Err {
        /// Echoed correlation ID from the client request.
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// Numeric error code (4xxx = client, 5xxx = server).
        code: u16,

        /// Human-readable error description (for logging only).
        msg: String,
    },

    /// Blob delivery (subscription push, backfill, or query result).
    ///
    /// Clients SHOULD verify `blob_id == SHA-256(blob)`.
    #[serde(rename = "BLOB")]
    Blob {
        /// The routing pseudonym this blob was published under.
        routing_id: [u8; 32],

        /// `SHA-256(blob)` -- the blob's content-addressed identifier.
        blob_id: [u8; 32],

        /// Optional recipient pseudonym from the original PUBLISH.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recipient_hint: Option<[u8; 32]>,

        /// The blob's TTL as set by the publisher.
        blob_ttl: u32,

        /// Unix timestamp when the relay stored this blob.
        stored_at: u64,

        /// The opaque encrypted blob.
        blob: Vec<u8>,
    },

    /// Protocol event notification.
    ///
    /// Known event types: `"backfill_complete"` (with `routing_id`),
    /// `"query_complete"` (with `count`).
    #[serde(rename = "EVENT")]
    Event {
        /// Echoed correlation ID from the originating request.
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// Event type identifier (e.g. `"backfill_complete"`,
        /// `"query_complete"`).
        #[serde(rename = "type")]
        event_type: String,
    },

    /// Keepalive response to a client [`ClientMessage::Ping`].
    #[serde(rename = "PONG")]
    Pong {
        /// Echoed client timestamp.
        ts: u64,
    },
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a [`ClientMessage`] to `MessagePack` bytes.
///
/// Uses named (map-based) serialization so that the `op` tag and all field
/// names are preserved as string keys in the `MessagePack` output.
///
/// # Errors
///
/// Returns [`ProtocolError::Serialization`] if encoding fails.
pub fn serialize_client_message(msg: &ClientMessage) -> Result<Vec<u8>, ProtocolError> {
    Ok(rmp_serde::to_vec_named(msg)?)
}

/// Deserialize a [`ClientMessage`] from `MessagePack` bytes.
///
/// # Errors
///
/// Returns [`ProtocolError::Deserialization`] if the bytes are not valid
/// `MessagePack` or do not match the expected schema.
pub fn deserialize_client_message(bytes: &[u8]) -> Result<ClientMessage, ProtocolError> {
    Ok(rmp_serde::from_slice(bytes)?)
}

/// Serialize a [`RelayMessage`] to `MessagePack` bytes.
///
/// Uses named (map-based) serialization so that the `op` tag and all field
/// names are preserved as string keys in the `MessagePack` output.
///
/// # Errors
///
/// Returns [`ProtocolError::Serialization`] if encoding fails.
pub fn serialize_relay_message(msg: &RelayMessage) -> Result<Vec<u8>, ProtocolError> {
    Ok(rmp_serde::to_vec_named(msg)?)
}

/// Deserialize a [`RelayMessage`] from `MessagePack` bytes.
///
/// # Errors
///
/// Returns [`ProtocolError::Deserialization`] if the bytes are not valid
/// `MessagePack` or do not match the expected schema.
pub fn deserialize_relay_message(bytes: &[u8]) -> Result<RelayMessage, ProtocolError> {
    Ok(rmp_serde::from_slice(bytes)?)
}

/// Validate a [`ClientMessage`] against ADR-004 constraints.
///
/// Checks:
/// - `blob_ttl` is in range 1..=604 800
/// - `blob` does not exceed 262 144 bytes
/// - `ref` does not exceed 64 bytes
///
/// # Errors
///
/// Returns the first constraint violation found.
pub fn validate_client_message(msg: &ClientMessage) -> Result<(), ProtocolError> {
    match msg {
        ClientMessage::Publish {
            ref_id,
            blob_ttl,
            blob,
            ..
        } => {
            validate_ref(ref_id.as_deref())?;
            validate_blob_ttl(*blob_ttl)?;
            validate_blob_size(blob)?;
        }
        ClientMessage::Subscribe { ref_id, .. }
        | ClientMessage::Unsubscribe { ref_id, .. }
        | ClientMessage::Query { ref_id, .. }
        | ClientMessage::Delete { ref_id, .. } => {
            validate_ref(ref_id.as_deref())?;
        }
        ClientMessage::Ack { .. } | ClientMessage::Ping { .. } => {}
    }
    Ok(())
}

/// Validate a `ref` (correlation ID) string length.
const fn validate_ref(ref_id: Option<&str>) -> Result<(), ProtocolError> {
    if let Some(r) = ref_id
        && r.len() > MAX_REF_LENGTH
    {
        return Err(ProtocolError::RefTooLong { length: r.len() });
    }
    Ok(())
}

/// Validate a `blob_ttl` value.
const fn validate_blob_ttl(ttl: u32) -> Result<(), ProtocolError> {
    if ttl < MIN_BLOB_TTL || ttl > MAX_BLOB_TTL {
        return Err(ProtocolError::BlobTtlOutOfRange { value: ttl });
    }
    Ok(())
}

/// Validate a blob's size.
const fn validate_blob_size(blob: &[u8]) -> Result<(), ProtocolError> {
    if blob.len() > MAX_BLOB_SIZE {
        return Err(ProtocolError::BlobTooLarge {
            size: blob.len(),
            max: MAX_BLOB_SIZE,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    /// Helper: a fixed 32-byte array for test routing IDs.
    fn test_routing_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        for (i, byte) in id.iter_mut().enumerate() {
            *byte = i as u8;
        }
        id
    }

    /// Helper: a different fixed 32-byte array for blob IDs.
    fn test_blob_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        for (i, byte) in id.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_add(100);
        }
        id
    }

    /// Helper: a fixed 32-byte array for recipient hints.
    fn test_recipient_hint() -> [u8; 32] {
        let mut id = [0u8; 32];
        for (i, byte) in id.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_add(200);
        }
        id
    }

    // -----------------------------------------------------------------------
    // ClientMessage roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_publish_all_fields() {
        let msg = ClientMessage::Publish {
            ref_id: Some("req-1".to_string()),
            routing_id: test_routing_id(),
            recipient_hint: Some(test_recipient_hint()),
            blob_ttl: 3600,
            blob: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let bytes = serialize_client_message(&msg).expect("serialize");
        let decoded = deserialize_client_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_publish_minimal() {
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: test_routing_id(),
            recipient_hint: None,
            blob_ttl: 1,
            blob: vec![42],
        };
        let bytes = serialize_client_message(&msg).expect("serialize");
        let decoded = deserialize_client_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_subscribe_with_since() {
        let msg = ClientMessage::Subscribe {
            ref_id: Some("sub-1".to_string()),
            routing_id: test_routing_id(),
            since: Some(1_700_000_000),
        };
        let bytes = serialize_client_message(&msg).expect("serialize");
        let decoded = deserialize_client_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_subscribe_minimal() {
        let msg = ClientMessage::Subscribe {
            ref_id: None,
            routing_id: test_routing_id(),
            since: None,
        };
        let bytes = serialize_client_message(&msg).expect("serialize");
        let decoded = deserialize_client_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_unsubscribe() {
        let msg = ClientMessage::Unsubscribe {
            ref_id: Some("unsub-1".to_string()),
            routing_id: test_routing_id(),
        };
        let bytes = serialize_client_message(&msg).expect("serialize");
        let decoded = deserialize_client_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_query_all_fields() {
        let msg = ClientMessage::Query {
            ref_id: Some("q-1".to_string()),
            routing_id: test_routing_id(),
            since: Some(1_700_000_000),
            limit: Some(50),
        };
        let bytes = serialize_client_message(&msg).expect("serialize");
        let decoded = deserialize_client_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_query_minimal() {
        let msg = ClientMessage::Query {
            ref_id: None,
            routing_id: test_routing_id(),
            since: None,
            limit: None,
        };
        let bytes = serialize_client_message(&msg).expect("serialize");
        let decoded = deserialize_client_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_delete() {
        let msg = ClientMessage::Delete {
            ref_id: Some("del-1".to_string()),
            blob_id: test_blob_id(),
        };
        let bytes = serialize_client_message(&msg).expect("serialize");
        let decoded = deserialize_client_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_ack() {
        let msg = ClientMessage::Ack {
            blob_id: test_blob_id(),
        };
        let bytes = serialize_client_message(&msg).expect("serialize");
        let decoded = deserialize_client_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_ping() {
        let msg = ClientMessage::Ping {
            ts: 1_700_000_000_000,
        };
        let bytes = serialize_client_message(&msg).expect("serialize");
        let decoded = deserialize_client_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    // -----------------------------------------------------------------------
    // RelayMessage roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_ok_with_blob_id() {
        let msg = RelayMessage::Ok {
            ref_id: Some("req-1".to_string()),
            blob_id: Some(test_blob_id()),
        };
        let bytes = serialize_relay_message(&msg).expect("serialize");
        let decoded = deserialize_relay_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_ok_minimal() {
        let msg = RelayMessage::Ok {
            ref_id: None,
            blob_id: None,
        };
        let bytes = serialize_relay_message(&msg).expect("serialize");
        let decoded = deserialize_relay_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_err() {
        let msg = RelayMessage::Err {
            ref_id: Some("req-2".to_string()),
            code: 4010,
            msg: "blob too large".to_string(),
        };
        let bytes = serialize_relay_message(&msg).expect("serialize");
        let decoded = deserialize_relay_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_blob_all_fields() {
        let msg = RelayMessage::Blob {
            routing_id: test_routing_id(),
            blob_id: test_blob_id(),
            recipient_hint: Some(test_recipient_hint()),
            blob_ttl: 7200,
            stored_at: 1_700_000_000,
            blob: vec![1, 2, 3, 4, 5],
        };
        let bytes = serialize_relay_message(&msg).expect("serialize");
        let decoded = deserialize_relay_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_blob_minimal() {
        let msg = RelayMessage::Blob {
            routing_id: test_routing_id(),
            blob_id: test_blob_id(),
            recipient_hint: None,
            blob_ttl: 1,
            stored_at: 0,
            blob: vec![42],
        };
        let bytes = serialize_relay_message(&msg).expect("serialize");
        let decoded = deserialize_relay_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_event() {
        let msg = RelayMessage::Event {
            ref_id: Some("sub-1".to_string()),
            event_type: "backfill_complete".to_string(),
        };
        let bytes = serialize_relay_message(&msg).expect("serialize");
        let decoded = deserialize_relay_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_event_query_complete() {
        let msg = RelayMessage::Event {
            ref_id: Some("q-1".to_string()),
            event_type: "query_complete".to_string(),
        };
        let bytes = serialize_relay_message(&msg).expect("serialize");
        let decoded = deserialize_relay_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_pong() {
        let msg = RelayMessage::Pong {
            ts: 1_700_000_000_000,
        };
        let bytes = serialize_relay_message(&msg).expect("serialize");
        let decoded = deserialize_relay_message(&bytes).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    // -----------------------------------------------------------------------
    // Binary field tests (32-byte identifiers)
    // -----------------------------------------------------------------------

    #[test]
    fn binary_fields_are_32_bytes_in_publish() {
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: [0xFF; 32],
            recipient_hint: Some([0xAA; 32]),
            blob_ttl: 100,
            blob: vec![1],
        };
        let bytes = serialize_client_message(&msg).expect("serialize");
        let decoded = deserialize_client_message(&bytes).expect("deserialize");
        let ClientMessage::Publish {
            routing_id,
            recipient_hint,
            ..
        } = decoded
        else {
            panic!("wrong variant");
        };
        assert_eq!(routing_id.len(), BINARY_ID_LENGTH);
        let hint = recipient_hint.expect("hint present");
        assert_eq!(hint.len(), BINARY_ID_LENGTH);
    }

    #[test]
    fn binary_fields_are_32_bytes_in_blob() {
        let msg = RelayMessage::Blob {
            routing_id: [0x11; 32],
            blob_id: [0x22; 32],
            recipient_hint: Some([0x33; 32]),
            blob_ttl: 100,
            stored_at: 12345,
            blob: vec![1],
        };
        let bytes = serialize_relay_message(&msg).expect("serialize");
        let decoded = deserialize_relay_message(&bytes).expect("deserialize");
        let RelayMessage::Blob {
            routing_id,
            blob_id,
            recipient_hint,
            ..
        } = decoded
        else {
            panic!("wrong variant");
        };
        assert_eq!(routing_id.len(), BINARY_ID_LENGTH);
        assert_eq!(blob_id.len(), BINARY_ID_LENGTH);
        let hint = recipient_hint.expect("hint present");
        assert_eq!(hint.len(), BINARY_ID_LENGTH);
    }

    // -----------------------------------------------------------------------
    // Validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_ttl_zero() {
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: test_routing_id(),
            recipient_hint: None,
            blob_ttl: 0,
            blob: vec![1],
        };
        let err = validate_client_message(&msg).unwrap_err();
        assert!(matches!(err, ProtocolError::BlobTtlOutOfRange { value: 0 }));
    }

    #[test]
    fn validate_rejects_ttl_too_large() {
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: test_routing_id(),
            recipient_hint: None,
            blob_ttl: MAX_BLOB_TTL + 1,
            blob: vec![1],
        };
        let err = validate_client_message(&msg).unwrap_err();
        assert!(matches!(err, ProtocolError::BlobTtlOutOfRange { .. }));
    }

    #[test]
    fn validate_rejects_oversized_blob() {
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: test_routing_id(),
            recipient_hint: None,
            blob_ttl: 100,
            blob: vec![0; MAX_BLOB_SIZE + 1],
        };
        let err = validate_client_message(&msg).unwrap_err();
        assert!(matches!(err, ProtocolError::BlobTooLarge { .. }));
    }

    #[test]
    fn validate_rejects_ref_too_long() {
        let msg = ClientMessage::Publish {
            ref_id: Some("x".repeat(MAX_REF_LENGTH + 1)),
            routing_id: test_routing_id(),
            recipient_hint: None,
            blob_ttl: 100,
            blob: vec![1],
        };
        let err = validate_client_message(&msg).unwrap_err();
        assert!(matches!(err, ProtocolError::RefTooLong { .. }));
    }

    #[test]
    fn validate_accepts_valid_publish() {
        let msg = ClientMessage::Publish {
            ref_id: Some("ok".to_string()),
            routing_id: test_routing_id(),
            recipient_hint: None,
            blob_ttl: 100,
            blob: vec![1, 2, 3],
        };
        validate_client_message(&msg).expect("should be valid");
    }

    #[test]
    fn validate_accepts_boundary_ttl_values() {
        // Minimum
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: test_routing_id(),
            recipient_hint: None,
            blob_ttl: MIN_BLOB_TTL,
            blob: vec![1],
        };
        validate_client_message(&msg).expect("min TTL valid");

        // Maximum
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: test_routing_id(),
            recipient_hint: None,
            blob_ttl: MAX_BLOB_TTL,
            blob: vec![1],
        };
        validate_client_message(&msg).expect("max TTL valid");
    }

    #[test]
    fn validate_accepts_max_size_blob() {
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: test_routing_id(),
            recipient_hint: None,
            blob_ttl: 100,
            blob: vec![0; MAX_BLOB_SIZE],
        };
        validate_client_message(&msg).expect("max blob size valid");
    }

    #[test]
    fn validate_accepts_max_length_ref() {
        let msg = ClientMessage::Subscribe {
            ref_id: Some("x".repeat(MAX_REF_LENGTH)),
            routing_id: test_routing_id(),
            since: None,
        };
        validate_client_message(&msg).expect("max ref length valid");
    }

    // -----------------------------------------------------------------------
    // Serialized format checks
    // -----------------------------------------------------------------------

    #[test]
    fn serialized_publish_contains_op_tag() {
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: [0; 32],
            recipient_hint: None,
            blob_ttl: 100,
            blob: vec![1],
        };
        let bytes = serialize_client_message(&msg).expect("serialize");
        // The serialized bytes should contain the "PUBLISH" op string
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("PUBLISH"),
            "serialized bytes should contain PUBLISH op tag"
        );
    }

    #[test]
    fn serialized_ok_contains_op_tag() {
        let msg = RelayMessage::Ok {
            ref_id: None,
            blob_id: None,
        };
        let bytes = serialize_relay_message(&msg).expect("serialize");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("OK"),
            "serialized bytes should contain OK op tag"
        );
    }

    // -----------------------------------------------------------------------
    // All 7 ClientMessage variants roundtrip in one test
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_all_client_message_variants() {
        let messages = vec![
            ClientMessage::Publish {
                ref_id: Some("p1".to_string()),
                routing_id: test_routing_id(),
                recipient_hint: Some(test_recipient_hint()),
                blob_ttl: 3600,
                blob: vec![1, 2, 3],
            },
            ClientMessage::Subscribe {
                ref_id: Some("s1".to_string()),
                routing_id: test_routing_id(),
                since: Some(1_000_000),
            },
            ClientMessage::Unsubscribe {
                ref_id: Some("u1".to_string()),
                routing_id: test_routing_id(),
            },
            ClientMessage::Query {
                ref_id: Some("q1".to_string()),
                routing_id: test_routing_id(),
                since: Some(500_000),
                limit: Some(50),
            },
            ClientMessage::Delete {
                ref_id: Some("d1".to_string()),
                blob_id: test_blob_id(),
            },
            ClientMessage::Ack {
                blob_id: test_blob_id(),
            },
            ClientMessage::Ping { ts: 99999 },
        ];

        for msg in messages {
            let bytes = serialize_client_message(&msg).expect("serialize");
            let decoded = deserialize_client_message(&bytes).expect("deserialize");
            assert_eq!(msg, decoded, "roundtrip failed for {msg:?}");
        }
    }

    // -----------------------------------------------------------------------
    // All 5 RelayMessage variants roundtrip in one test
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_all_relay_message_variants() {
        let messages = vec![
            RelayMessage::Ok {
                ref_id: Some("r1".to_string()),
                blob_id: Some(test_blob_id()),
            },
            RelayMessage::Err {
                ref_id: Some("r2".to_string()),
                code: 4000,
                msg: "invalid message".to_string(),
            },
            RelayMessage::Blob {
                routing_id: test_routing_id(),
                blob_id: test_blob_id(),
                recipient_hint: Some(test_recipient_hint()),
                blob_ttl: 1800,
                stored_at: 1_700_000_000,
                blob: vec![10, 20, 30],
            },
            RelayMessage::Event {
                ref_id: Some("r3".to_string()),
                event_type: "backfill_complete".to_string(),
            },
            RelayMessage::Pong { ts: 42 },
        ];

        for msg in messages {
            let bytes = serialize_relay_message(&msg).expect("serialize");
            let decoded = deserialize_relay_message(&bytes).expect("deserialize");
            assert_eq!(msg, decoded, "roundtrip failed for {msg:?}");
        }
    }

    // -----------------------------------------------------------------------
    // Deserialization error tests
    // -----------------------------------------------------------------------

    #[test]
    fn deserialize_invalid_bytes_returns_error() {
        let result = deserialize_client_message(&[0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_empty_bytes_returns_error() {
        let result = deserialize_client_message(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_relay_invalid_bytes_returns_error() {
        let result = deserialize_relay_message(&[0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }
}
