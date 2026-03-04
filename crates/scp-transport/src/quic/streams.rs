//! Per-operation QUIC stream helpers.
//!
//! Each SCP operation maps to a dedicated QUIC bidirectional stream (section 10.14.1):
//!
//! | Operation | Stream lifecycle |
//! |-----------|-----------------|
//! | PUBLISH   | Open bidi -> send PUBLISH frame -> receive ACK/ERR -> close |
//! | SUBSCRIBE | Open bidi -> send SUBSCRIBE frame -> receive BLOBs until close |
//! | QUERY     | Open bidi -> send QUERY frame -> receive BLOBs + `query_complete` -> close |
//! | DELETE    | Open bidi -> send DELETE frame -> receive ACK/ERR -> close |
//!
//! All frames use the same `MessagePack` wire format as ADR-004. The `ref_id` field
//! is not required for QUIC (responses are scoped to their stream) but MAY be
//! included for logging/debugging per section 10.14.1.
//!
//! See ADR-037 in `.docs/adrs/phase-2.md` for design rationale.

use serde::{Deserialize, Serialize};

use crate::error::TransportError;

// ---------------------------------------------------------------------------
// Wire frame types (MessagePack, same schema as ADR-004)
// ---------------------------------------------------------------------------

/// Length-prefixed framing: each `MessagePack` message is preceded by a 4-byte
/// big-endian length prefix on the QUIC stream. This lets the receiver know
/// exactly how many bytes to read for each frame.
pub const LENGTH_PREFIX_SIZE: usize = 4;

/// Maximum frame size (256 KB + overhead for `MessagePack` map keys/metadata).
/// Matches the `MAX_BLOB_SIZE` (262144) from ADR-004 plus generous overhead.
pub const MAX_FRAME_SIZE: u32 = 512_000;

/// Client-to-relay frame sent on a QUIC stream.
///
/// Same field semantics as [`ClientMessage`](crate::native::protocol::ClientMessage)
/// from ADR-004. The `op` field is used as the serde tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum QuicClientFrame {
    /// Publish a blob to subscribers of a routing ID.
    #[serde(rename = "PUBLISH")]
    Publish {
        /// Per-context pseudonym for routing (32 bytes).
        #[serde(with = "serde_bytes")]
        routing_id: [u8; 32],

        /// Optional recipient pseudonym for directed delivery (32 bytes).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "byte_array_32_opt"
        )]
        recipient_hint: Option<[u8; 32]>,

        /// How long (seconds) the relay should store this blob.
        blob_ttl: u32,

        /// The opaque blob content.
        #[serde(with = "serde_bytes")]
        blob: Vec<u8>,
    },

    /// Subscribe to blobs for a routing ID.
    #[serde(rename = "SUBSCRIBE")]
    Subscribe {
        /// Per-context pseudonym to subscribe to (32 bytes).
        #[serde(with = "serde_bytes")]
        routing_id: [u8; 32],

        /// Optional unix timestamp; backfill stored blobs newer than this.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since: Option<u64>,
    },

    /// One-shot query for stored blobs matching a routing ID.
    #[serde(rename = "QUERY")]
    Query {
        /// Per-context pseudonym to query (32 bytes).
        #[serde(with = "serde_bytes")]
        routing_id: [u8; 32],

        /// Optional unix timestamp; return only blobs newer than this.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since: Option<u64>,

        /// Maximum number of blobs to return. Default 100, max 1000.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
    },

    /// Request deletion of a blob by its ID.
    #[serde(rename = "DELETE")]
    Delete {
        /// SHA-256 hash identifying the blob (32 bytes).
        #[serde(with = "serde_bytes")]
        blob_id: [u8; 32],
    },
}

/// Relay-to-client frame received on a QUIC stream.
///
/// Same field semantics as [`RelayMessage`](crate::native::protocol::RelayMessage)
/// from ADR-004. The `op` field is used as the serde tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum QuicRelayFrame {
    /// Successful response.
    #[serde(rename = "OK")]
    Ok {
        /// Blob ID assigned by the relay (for PUBLISH responses).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "byte_array_32_opt"
        )]
        blob_id: Option<[u8; 32]>,
    },

    /// Error response.
    #[serde(rename = "ERR")]
    Err {
        /// Numeric error code.
        code: u32,
        /// Human-readable error message.
        msg: String,
    },

    /// A blob delivered to the client.
    #[serde(rename = "BLOB")]
    Blob {
        /// Per-context pseudonym (32 bytes).
        #[serde(with = "serde_bytes")]
        routing_id: [u8; 32],

        /// SHA-256 hash of the blob (32 bytes).
        #[serde(with = "serde_bytes")]
        blob_id: [u8; 32],

        /// Optional recipient pseudonym (32 bytes).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "byte_array_32_opt"
        )]
        recipient_hint: Option<[u8; 32]>,

        /// How long (seconds) the relay stores this blob.
        blob_ttl: u32,

        /// Unix timestamp when the relay stored this blob.
        stored_at: u64,

        /// The opaque blob content.
        #[serde(with = "serde_bytes")]
        blob: Vec<u8>,
    },

    /// Protocol-level event (e.g., `backfill_complete`, `query_complete`).
    #[serde(rename = "EVENT")]
    Event {
        /// Event type string.
        event_type: String,
    },
}

// ---------------------------------------------------------------------------
// Serde helper for Option<[u8; 32]> as MessagePack binary
// ---------------------------------------------------------------------------

/// Serde helper module for `Option<[u8; 32]>` fields that must be encoded as
/// `MessagePack` binary (not arrays of integers).
mod byte_array_32_opt {
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    #[allow(clippy::ref_option)]
    pub fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(arr) => serializer.serialize_bytes(arr),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        let opt: Option<serde_bytes::ByteBuf> = serde::Deserialize::deserialize(deserializer)?;
        match opt {
            None => Ok(None),
            Some(buf) => {
                let bytes: [u8; 32] = buf.into_vec().try_into().map_err(|v: Vec<u8>| {
                    D::Error::custom(format!("expected 32 bytes, got {}", v.len()))
                })?;
                Ok(Some(bytes))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Frame I/O: length-prefixed MessagePack over QUIC streams
// ---------------------------------------------------------------------------

/// Serializes a client frame to length-prefixed `MessagePack` bytes.
///
/// Format: `[4-byte big-endian length][MessagePack payload]`
///
/// # Errors
///
/// Returns [`TransportError::SendFailed`] if serialization fails or the frame
/// exceeds [`MAX_FRAME_SIZE`].
pub fn encode_client_frame(frame: &QuicClientFrame) -> Result<Vec<u8>, TransportError> {
    let payload =
        rmp_serde::to_vec_named(frame).map_err(|e| TransportError::SendFailed(e.to_string()))?;
    let len = u32::try_from(payload.len()).map_err(|_| {
        TransportError::SendFailed(format!("frame too large: {} bytes", payload.len()))
    })?;
    if len > MAX_FRAME_SIZE {
        return Err(TransportError::SendFailed(format!(
            "frame exceeds maximum size: {len} > {MAX_FRAME_SIZE}"
        )));
    }
    let mut buf = Vec::with_capacity(LENGTH_PREFIX_SIZE + payload.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Serializes a relay frame to length-prefixed `MessagePack` bytes.
///
/// Format: `[4-byte big-endian length][MessagePack payload]`
///
/// # Errors
///
/// Returns [`TransportError::SendFailed`] if serialization fails or the frame
/// exceeds [`MAX_FRAME_SIZE`].
pub fn encode_relay_frame(frame: &QuicRelayFrame) -> Result<Vec<u8>, TransportError> {
    let payload =
        rmp_serde::to_vec_named(frame).map_err(|e| TransportError::SendFailed(e.to_string()))?;
    let len = u32::try_from(payload.len()).map_err(|_| {
        TransportError::SendFailed(format!("frame too large: {} bytes", payload.len()))
    })?;
    if len > MAX_FRAME_SIZE {
        return Err(TransportError::SendFailed(format!(
            "frame exceeds maximum size: {len} > {MAX_FRAME_SIZE}"
        )));
    }
    let mut buf = Vec::with_capacity(LENGTH_PREFIX_SIZE + payload.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Reads a length-prefixed frame from a byte buffer.
///
/// Returns the number of bytes consumed and the raw payload. Callers should
/// deserialize the payload with `rmp_serde::from_slice`.
///
/// Returns `None` if the buffer does not contain a complete frame.
///
/// # Errors
///
/// Returns [`TransportError::ProtocolError`] if the frame length exceeds
/// [`MAX_FRAME_SIZE`].
pub fn decode_frame_from_buf(buf: &[u8]) -> Result<Option<(usize, Vec<u8>)>, TransportError> {
    if buf.len() < LENGTH_PREFIX_SIZE {
        return Ok(None);
    }
    let len_bytes: [u8; 4] = buf[..LENGTH_PREFIX_SIZE]
        .try_into()
        .map_err(|_| TransportError::ProtocolError("invalid length prefix".to_string()))?;
    let frame_len = u32::from_be_bytes(len_bytes);
    if frame_len > MAX_FRAME_SIZE {
        return Err(TransportError::ProtocolError(format!(
            "frame length exceeds maximum: {frame_len} > {MAX_FRAME_SIZE}"
        )));
    }
    let total = LENGTH_PREFIX_SIZE + frame_len as usize;
    if buf.len() < total {
        return Ok(None);
    }
    let payload = buf[LENGTH_PREFIX_SIZE..total].to_vec();
    Ok(Some((total, payload)))
}

/// Deserializes a relay frame from raw `MessagePack` bytes.
///
/// # Errors
///
/// Returns [`TransportError::ProtocolError`] if deserialization fails.
pub fn decode_relay_frame(payload: &[u8]) -> Result<QuicRelayFrame, TransportError> {
    rmp_serde::from_slice(payload)
        .map_err(|e| TransportError::ProtocolError(format!("invalid relay frame: {e}")))
}

/// Deserializes a client frame from raw `MessagePack` bytes.
///
/// # Errors
///
/// Returns [`TransportError::ProtocolError`] if deserialization fails.
pub fn decode_client_frame(payload: &[u8]) -> Result<QuicClientFrame, TransportError> {
    rmp_serde::from_slice(payload)
        .map_err(|e| TransportError::ProtocolError(format!("invalid client frame: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_publish_frame_roundtrip() {
        let frame = QuicClientFrame::Publish {
            routing_id: [0xAA; 32],
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![0x01, 0x02, 0x03],
        };
        let encoded = encode_client_frame(&frame).unwrap();
        assert!(encoded.len() > LENGTH_PREFIX_SIZE);

        let (consumed, payload) = decode_frame_from_buf(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());

        let decoded = decode_client_frame(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn encode_decode_subscribe_frame_roundtrip() {
        let frame = QuicClientFrame::Subscribe {
            routing_id: [0xBB; 32],
            since: Some(1_700_000_000),
        };
        let encoded = encode_client_frame(&frame).unwrap();
        let (_, payload) = decode_frame_from_buf(&encoded).unwrap().unwrap();
        let decoded = decode_client_frame(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn encode_decode_query_frame_roundtrip() {
        let frame = QuicClientFrame::Query {
            routing_id: [0xCC; 32],
            since: Some(1_700_000_000),
            limit: Some(50),
        };
        let encoded = encode_client_frame(&frame).unwrap();
        let (_, payload) = decode_frame_from_buf(&encoded).unwrap().unwrap();
        let decoded = decode_client_frame(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn encode_decode_delete_frame_roundtrip() {
        let frame = QuicClientFrame::Delete {
            blob_id: [0xDD; 32],
        };
        let encoded = encode_client_frame(&frame).unwrap();
        let (_, payload) = decode_frame_from_buf(&encoded).unwrap().unwrap();
        let decoded = decode_client_frame(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn encode_decode_ok_relay_frame_roundtrip() {
        let frame = QuicRelayFrame::Ok {
            blob_id: Some([0xEE; 32]),
        };
        let encoded = encode_relay_frame(&frame).unwrap();
        let (_, payload) = decode_frame_from_buf(&encoded).unwrap().unwrap();
        let decoded = decode_relay_frame(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn encode_decode_err_relay_frame_roundtrip() {
        let frame = QuicRelayFrame::Err {
            code: 4001,
            msg: "invalid message".to_string(),
        };
        let encoded = encode_relay_frame(&frame).unwrap();
        let (_, payload) = decode_frame_from_buf(&encoded).unwrap().unwrap();
        let decoded = decode_relay_frame(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn encode_decode_blob_relay_frame_roundtrip() {
        let frame = QuicRelayFrame::Blob {
            routing_id: [0xAA; 32],
            blob_id: [0xBB; 32],
            recipient_hint: Some([0xCC; 32]),
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: vec![0x01, 0x02, 0x03],
        };
        let encoded = encode_relay_frame(&frame).unwrap();
        let (_, payload) = decode_frame_from_buf(&encoded).unwrap().unwrap();
        let decoded = decode_relay_frame(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn encode_decode_event_relay_frame_roundtrip() {
        let frame = QuicRelayFrame::Event {
            event_type: "query_complete".to_string(),
        };
        let encoded = encode_relay_frame(&frame).unwrap();
        let (_, payload) = decode_frame_from_buf(&encoded).unwrap().unwrap();
        let decoded = decode_relay_frame(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn decode_incomplete_buffer_returns_none() {
        // Only 2 bytes -- not enough for the length prefix.
        let buf = [0x00, 0x01];
        assert!(decode_frame_from_buf(&buf).unwrap().is_none());
    }

    #[test]
    fn decode_partial_payload_returns_none() {
        // Length prefix says 100 bytes, but only 4 + 10 bytes available.
        let mut buf = vec![0x00, 0x00, 0x00, 100];
        buf.extend_from_slice(&[0x00; 10]);
        assert!(decode_frame_from_buf(&buf).unwrap().is_none());
    }

    #[test]
    fn decode_oversized_frame_returns_error() {
        // Length prefix exceeds MAX_FRAME_SIZE.
        let len = MAX_FRAME_SIZE + 1;
        let buf = len.to_be_bytes();
        let err = decode_frame_from_buf(&buf).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn publish_frame_with_recipient_hint_roundtrip() {
        let frame = QuicClientFrame::Publish {
            routing_id: [0x11; 32],
            recipient_hint: Some([0x22; 32]),
            blob_ttl: 7200,
            blob: vec![0xAA; 100],
        };
        let encoded = encode_client_frame(&frame).unwrap();
        let (_, payload) = decode_frame_from_buf(&encoded).unwrap().unwrap();
        let decoded = decode_client_frame(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn ok_frame_without_blob_id_roundtrip() {
        let frame = QuicRelayFrame::Ok { blob_id: None };
        let encoded = encode_relay_frame(&frame).unwrap();
        let (_, payload) = decode_frame_from_buf(&encoded).unwrap().unwrap();
        let decoded = decode_relay_frame(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn blob_without_recipient_hint_roundtrip() {
        let frame = QuicRelayFrame::Blob {
            routing_id: [0x33; 32],
            blob_id: [0x44; 32],
            recipient_hint: None,
            blob_ttl: 1800,
            stored_at: 1_700_000_500,
            blob: vec![0xFF; 50],
        };
        let encoded = encode_relay_frame(&frame).unwrap();
        let (_, payload) = decode_frame_from_buf(&encoded).unwrap().unwrap();
        let decoded = decode_relay_frame(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn multiple_frames_in_buffer() {
        let frame1 = QuicClientFrame::Delete {
            blob_id: [0x55; 32],
        };
        let frame2 = QuicClientFrame::Query {
            routing_id: [0x66; 32],
            since: None,
            limit: None,
        };
        let mut buf = encode_client_frame(&frame1).unwrap();
        buf.extend_from_slice(&encode_client_frame(&frame2).unwrap());

        // Decode first frame.
        let (consumed1, payload1) = decode_frame_from_buf(&buf).unwrap().unwrap();
        let decoded1 = decode_client_frame(&payload1).unwrap();
        assert_eq!(decoded1, frame1);

        // Decode second frame from remaining buffer.
        let (consumed2, payload2) = decode_frame_from_buf(&buf[consumed1..]).unwrap().unwrap();
        let decoded2 = decode_client_frame(&payload2).unwrap();
        assert_eq!(decoded2, frame2);
        assert_eq!(consumed1 + consumed2, buf.len());
    }

    #[test]
    fn subscribe_without_since_roundtrip() {
        let frame = QuicClientFrame::Subscribe {
            routing_id: [0x77; 32],
            since: None,
        };
        let encoded = encode_client_frame(&frame).unwrap();
        let (_, payload) = decode_frame_from_buf(&encoded).unwrap().unwrap();
        let decoded = decode_client_frame(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn query_minimal_roundtrip() {
        let frame = QuicClientFrame::Query {
            routing_id: [0x88; 32],
            since: None,
            limit: None,
        };
        let encoded = encode_client_frame(&frame).unwrap();
        let (_, payload) = decode_frame_from_buf(&encoded).unwrap().unwrap();
        let decoded = decode_client_frame(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn backfill_complete_event_roundtrip() {
        let frame = QuicRelayFrame::Event {
            event_type: "backfill_complete".to_string(),
        };
        let encoded = encode_relay_frame(&frame).unwrap();
        let (_, payload) = decode_frame_from_buf(&encoded).unwrap().unwrap();
        let decoded = decode_relay_frame(&payload).unwrap();
        assert_eq!(decoded, frame);
    }
}
