//! Native relay protocol message types and `MessagePack` wire format.
//!
//! Defines [`ClientMessage`] (client-to-relay) and [`RelayMessage`]
//! (relay-to-client) enums with `serde` support for `MessagePack`
//! serialization via `rmp-serde`. Every message is a `MessagePack` map with a
//! required `op` field (string) plus operation-specific fields.
//!
//! # Wire format
//!
//! Messages are serialized as `MessagePack` maps over WebSocket binary frames.
//! All binary fields (`routing_id`, `blob_id`, `recipient_hint`, `blob`) use
//! `MessagePack`'s native `bin` type -- no Base64 or hex encoding.
//!
//! Unknown fields are ignored on deserialization for forward compatibility.
//!
//! # Constraints
//!
//! - `blob_ttl`: 1--604800 (7 days)
//! - `blob`: 1--262144 bytes (256 KB)
//! - `ref_id`: max 64 bytes when present
//! - `routing_id`, `recipient_hint`, `blob_id`: exactly 32 bytes
//! - `limit` (QUERY): default 100, max 1000
//!
//! Use [`ClientMessage::validate`] to check constraints before sending.
//!
//! See ADR-004 in `.docs/adrs/phase-1.md` for the full wire format specification.

use serde::{Deserialize, Serialize};

use super::error::NativeProtocolError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum blob size in bytes (256 KB).
pub const MAX_BLOB_SIZE: usize = 262_144;

/// Minimum blob TTL in seconds (1 second).
pub const MIN_BLOB_TTL: u32 = 1;

/// Maximum blob TTL in seconds (7 days).
pub const MAX_BLOB_TTL: u32 = 604_800;

/// Maximum `ref_id` length in bytes.
pub const MAX_REF_ID_LEN: usize = 64;

/// Default QUERY limit when not specified.
pub const DEFAULT_QUERY_LIMIT: u32 = 100;

/// Maximum QUERY limit.
pub const MAX_QUERY_LIMIT: u32 = 1000;

// ---------------------------------------------------------------------------
// Serde helper for Option<[u8; 32]> as MessagePack binary
// ---------------------------------------------------------------------------

/// Serde helper module for `Option<[u8; 32]>` fields that must be encoded as
/// `MessagePack` binary (not arrays of integers).
///
/// Uses `serde_bytes` internally for the `Some` case and handles `None`
/// transparently.
mod byte_array_32_opt {
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    // serde Serialize signature requires &Option<T>.
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
// ClientMessage
// ---------------------------------------------------------------------------

/// Client-to-relay operations sent over WebSocket binary frames.
///
/// Each variant maps to a wire-format `MessagePack` map with an `op` field
/// identifying the operation. Serialize with [`ClientMessage::to_bytes`] and
/// deserialize with [`ClientMessage::from_bytes`].
///
/// # Variants
///
/// | Variant | Op | Description |
/// |---------|------|-------------|
/// | [`Publish`](ClientMessage::Publish) | `PUBLISH` | Store a blob for subscribers |
/// | [`Subscribe`](ClientMessage::Subscribe) | `SUBSCRIBE` | Subscribe to a routing ID |
/// | [`Unsubscribe`](ClientMessage::Unsubscribe) | `UNSUBSCRIBE` | Stop receiving blobs |
/// | [`Query`](ClientMessage::Query) | `QUERY` | One-shot query for stored blobs |
/// | [`Delete`](ClientMessage::Delete) | `DELETE` | Request blob deletion |
/// | [`Ack`](ClientMessage::Ack) | `ACK` | Delivery receipt |
/// | [`Ping`](ClientMessage::Ping) | `PING` | Keepalive |
/// | [`BridgeRegister`](ClientMessage::BridgeRegister) | `BRIDGE_REGISTER` | Register a routing ID for bridge proxying (section 10.12.4) |
/// | [`BridgeData`](ClientMessage::BridgeData) | `BRIDGE_DATA` | Send proxied data through a bridge (section 10.12.4) |
///
/// See ADR-004 in `.docs/adrs/phase-1.md` for the full specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum ClientMessage {
    /// Publish a blob to subscribers of a routing ID.
    ///
    /// The relay stores the blob for `blob_ttl` seconds and delivers it to
    /// active subscribers. Returns an `Ok` response with the `blob_id`
    /// (SHA-256 hash of the blob).
    #[serde(rename = "PUBLISH")]
    Publish {
        /// Client-assigned request ID, echoed in the relay response.
        /// Maximum 64 bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

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
        /// Valid range: 1--604800 (7 days).
        blob_ttl: u32,

        /// The opaque blob content. 1--262144 bytes (256 KB).
        #[serde(with = "serde_bytes")]
        blob: Vec<u8>,
    },

    /// Subscribe to blobs for a routing ID.
    ///
    /// The relay pushes new blobs via `BLOB` messages. If `since` is provided,
    /// stored blobs newer than that timestamp are backfilled first (oldest-first),
    /// followed by an `EVENT { type: "backfill_complete" }`.
    #[serde(rename = "SUBSCRIBE")]
    Subscribe {
        /// Client-assigned request ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// Per-context pseudonym to subscribe to (32 bytes).
        #[serde(with = "serde_bytes")]
        routing_id: [u8; 32],

        /// Optional unix timestamp; backfill stored blobs newer than this.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since: Option<u64>,
    },

    /// Stop receiving blobs for a routing ID.
    #[serde(rename = "UNSUBSCRIBE")]
    Unsubscribe {
        /// Client-assigned request ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// Per-context pseudonym to unsubscribe from (32 bytes).
        #[serde(with = "serde_bytes")]
        routing_id: [u8; 32],
    },

    /// One-shot query for stored blobs matching a routing ID.
    ///
    /// Returns matching blobs as `BLOB` messages, followed by an
    /// `EVENT { type: "query_complete" }`. Does not create a subscription.
    #[serde(rename = "QUERY")]
    Query {
        /// Client-assigned request ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

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
    ///
    /// Best-effort: the relay is untrusted and may not comply.
    #[serde(rename = "DELETE")]
    Delete {
        /// Client-assigned request ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// SHA-256 hash identifying the blob (32 bytes).
        #[serde(with = "serde_bytes")]
        blob_id: [u8; 32],
    },

    /// Delivery acknowledgement (fire-and-forget, no relay response).
    ///
    /// The relay MAY use ACKs from all known subscribers to garbage-collect
    /// blobs before TTL expiry.
    #[serde(rename = "ACK")]
    Ack {
        /// SHA-256 hash identifying the acknowledged blob (32 bytes).
        #[serde(with = "serde_bytes")]
        blob_id: [u8; 32],
    },

    /// Keepalive ping. Client MUST send every 30 seconds.
    ///
    /// The relay responds with `PONG` echoing the timestamp.
    #[serde(rename = "PING")]
    Ping {
        /// Client-chosen timestamp (typically current unix epoch seconds).
        ts: u64,
    },

    /// Register a routing ID for bridge proxying (spec section 10.12.4).
    ///
    /// Sent by a self-hosted relay behind symmetric NAT to a bridge relay.
    /// The self-hosted relay connects outbound to the bridge and registers
    /// its routing ID so the bridge can forward traffic for that ID over
    /// this connection.
    ///
    /// # Authentication (SCP-247)
    ///
    /// The message MUST include an Ed25519 signature proving the sender
    /// owns the DID that maps to the claimed `routing_id`. The signature
    /// covers `routing_id || timestamp` (concatenated bytes, big-endian
    /// timestamp). The relay responds with `OK` on success, `ERR` with
    /// code `BRIDGE_AUTH_FAILED` (4034) if authentication fails, or `ERR`
    /// with `BRIDGE_NOT_SUPPORTED` (4030) if bridging is not enabled.
    #[serde(rename = "BRIDGE_REGISTER")]
    BridgeRegister {
        /// Client-assigned request ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// The routing ID to register for bridge proxying (32 bytes).
        #[serde(with = "serde_bytes")]
        routing_id: [u8; 32],

        /// Ed25519 public key of the DID owner (32 bytes). The relay derives
        /// the DID string from this key and verifies that
        /// `SHA-256("scp:did:" || did_string) == routing_id` (SCP-247).
        #[serde(with = "serde_bytes")]
        public_key: [u8; 32],

        /// Ed25519 signature over `routing_id || timestamp` (64 bytes).
        /// Proves the sender holds the private key for `public_key` (SCP-247).
        #[serde(with = "serde_bytes")]
        signature: [u8; 64],

        /// Unix timestamp (seconds since epoch) included in the signed payload.
        /// Must be within 60 seconds of the server's current time (SCP-247).
        timestamp: u64,

        /// URL hint for reaching this self-hosted relay directly (used for
        /// informational purposes and potential future direct connection).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_relay_hint: Option<String>,
    },

    /// Send proxied data through a bridge to a registered self-hosted relay
    /// (spec section 10.12.4).
    ///
    /// Sent by peers to a bridge relay. The bridge forwards the payload
    /// to the registered self-hosted relay without inspection, modification,
    /// or caching — a transparent pipe.
    #[serde(rename = "BRIDGE_DATA")]
    BridgeData {
        /// Client-assigned request ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// The routing ID of the target self-hosted relay (32 bytes).
        #[serde(with = "serde_bytes")]
        target_routing_id: [u8; 32],

        /// Opaque payload to forward. The bridge does NOT inspect this.
        #[serde(with = "serde_bytes")]
        payload: Vec<u8>,
    },
}

impl ClientMessage {
    /// Serializes this message to `MessagePack` binary format.
    ///
    /// Uses named map representation so that the `op` tag and all field names
    /// are preserved in the wire format.
    ///
    /// # Errors
    ///
    /// Returns [`NativeProtocolError::SerializationFailed`] if serialization
    /// fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, NativeProtocolError> {
        rmp_serde::to_vec_named(self)
            .map_err(|e| NativeProtocolError::SerializationFailed(e.to_string()))
    }

    /// Deserializes a `ClientMessage` from `MessagePack` binary format.
    ///
    /// Unknown fields are silently ignored for forward compatibility.
    ///
    /// # Errors
    ///
    /// Returns [`NativeProtocolError::DeserializationFailed`] if the bytes
    /// are not a valid `MessagePack`-encoded `ClientMessage`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NativeProtocolError> {
        rmp_serde::from_slice(bytes)
            .map_err(|e| NativeProtocolError::DeserializationFailed(e.to_string()))
    }

    /// Validates this message against protocol constraints.
    ///
    /// Checks:
    /// - `ref_id` length (max 64 bytes)
    /// - `blob_ttl` range (1--604800)
    /// - `blob` size (1--262144 bytes)
    /// - `limit` range (1--1000)
    ///
    /// # Errors
    ///
    /// Returns [`NativeProtocolError::ValidationFailed`] describing the first
    /// constraint violation found.
    pub fn validate(&self) -> Result<(), NativeProtocolError> {
        match self {
            Self::Publish {
                ref_id,
                blob_ttl,
                blob,
                ..
            } => {
                validate_ref_id(ref_id)?;
                validate_blob_ttl(*blob_ttl)?;
                validate_blob(blob)?;
            }
            Self::Subscribe { ref_id, .. }
            | Self::Unsubscribe { ref_id, .. }
            | Self::Delete { ref_id, .. }
            | Self::BridgeRegister { ref_id, .. } => {
                validate_ref_id(ref_id)?;
            }
            Self::Query { ref_id, limit, .. } => {
                validate_ref_id(ref_id)?;
                if let Some(l) = limit
                    && (*l == 0 || *l > MAX_QUERY_LIMIT)
                {
                    return Err(NativeProtocolError::ValidationFailed(format!(
                        "limit must be 1-{MAX_QUERY_LIMIT}, got {l}"
                    )));
                }
            }
            Self::Ack { .. } | Self::Ping { .. } => {}
            Self::BridgeData {
                ref_id, payload, ..
            } => {
                validate_ref_id(ref_id)?;
                // Bridge payload has the same max size as a blob.
                if payload.is_empty() || payload.len() > MAX_BLOB_SIZE {
                    return Err(NativeProtocolError::ValidationFailed(format!(
                        "bridge payload must be 1-{MAX_BLOB_SIZE} bytes, got {}",
                        payload.len()
                    )));
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RelayMessage
// ---------------------------------------------------------------------------

/// Relay-to-client operations received over WebSocket binary frames.
///
/// Each variant maps to a wire-format `MessagePack` map with an `op` field
/// identifying the operation. Serialize with [`RelayMessage::to_bytes`] and
/// deserialize with [`RelayMessage::from_bytes`].
///
/// # Variants
///
/// | Variant | Op | Description |
/// |---------|------|-------------|
/// | [`Ok`](RelayMessage::Ok) | `OK` | Success response |
/// | [`Err`](RelayMessage::Err) | `ERR` | Error response with code |
/// | [`Blob`](RelayMessage::Blob) | `BLOB` | Blob delivery |
/// | [`Event`](RelayMessage::Event) | `EVENT` | Protocol event |
/// | [`Pong`](RelayMessage::Pong) | `PONG` | Keepalive response |
/// | [`BridgeData`](RelayMessage::BridgeData) | `BRIDGE_DATA` | Proxied data from bridge (section 10.12.4) |
///
/// See ADR-004 in `.docs/adrs/phase-1.md` for the full specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum RelayMessage {
    /// Success response.
    ///
    /// `blob_id` is present only in response to `PUBLISH` (the SHA-256 hash
    /// of the stored blob).
    #[serde(rename = "OK")]
    Ok {
        /// Echoed client request ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// Blob identifier (present only for PUBLISH responses).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "byte_array_32_opt"
        )]
        blob_id: Option<[u8; 32]>,
    },

    /// Error response with a numeric code and human-readable message.
    ///
    /// The `msg` field is for logging only -- clients MUST NOT parse it.
    /// Use [`code::is_client_error`](super::error::code::is_client_error) and
    /// [`code::is_server_error`](super::error::code::is_server_error) to
    /// determine retry strategy.
    #[serde(rename = "ERR")]
    Err {
        /// Echoed client request ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// Numeric error code (4xxx = client, 5xxx = server).
        code: u16,

        /// Human-readable error description (for logging, not parsing).
        msg: String,
    },

    /// Blob delivery from a subscription, backfill, or query.
    ///
    /// `blob_id` is the SHA-256 hash of `blob` -- clients SHOULD verify.
    #[serde(rename = "BLOB")]
    Blob {
        /// Per-context pseudonym this blob was published to (32 bytes).
        #[serde(with = "serde_bytes")]
        routing_id: [u8; 32],

        /// SHA-256 hash identifying the blob (32 bytes).
        #[serde(with = "serde_bytes")]
        blob_id: [u8; 32],

        /// Optional recipient pseudonym (32 bytes).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "byte_array_32_opt"
        )]
        recipient_hint: Option<[u8; 32]>,

        /// TTL at time of storage (seconds).
        blob_ttl: u32,

        /// Unix timestamp when the relay stored the blob.
        stored_at: u64,

        /// The opaque blob content.
        #[serde(with = "serde_bytes")]
        blob: Vec<u8>,
    },

    /// Protocol event notification.
    ///
    /// Known event types:
    /// - `"backfill_complete"` -- all stored blobs for a subscription have
    ///   been delivered.
    /// - `"query_complete"` -- all matching blobs for a query have been
    ///   delivered.
    #[serde(rename = "EVENT")]
    Event {
        /// Echoed client request ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// Event type identifier (e.g., `"backfill_complete"`,
        /// `"query_complete"`).
        event_type: String,
    },

    /// Keepalive response echoing the client's timestamp.
    #[serde(rename = "PONG")]
    Pong {
        /// The timestamp from the client's `PING`.
        ts: u64,
    },

    /// Proxied data delivered through a bridge relay (spec section 10.12.4).
    ///
    /// The bridge relay forwards this opaque payload from a peer or
    /// self-hosted relay. The bridge does NOT inspect, modify, or cache
    /// the payload.
    #[serde(rename = "BRIDGE_DATA")]
    BridgeData {
        /// The routing ID of the source (32 bytes).
        #[serde(with = "serde_bytes")]
        source_routing_id: [u8; 32],

        /// Opaque payload forwarded through the bridge.
        #[serde(with = "serde_bytes")]
        payload: Vec<u8>,
    },
}

impl RelayMessage {
    /// Serializes this message to `MessagePack` binary format.
    ///
    /// Uses named map representation so that the `op` tag and all field names
    /// are preserved in the wire format.
    ///
    /// # Errors
    ///
    /// Returns [`NativeProtocolError::SerializationFailed`] if serialization
    /// fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, NativeProtocolError> {
        rmp_serde::to_vec_named(self)
            .map_err(|e| NativeProtocolError::SerializationFailed(e.to_string()))
    }

    /// Deserializes a `RelayMessage` from `MessagePack` binary format.
    ///
    /// Unknown fields are silently ignored for forward compatibility.
    ///
    /// # Errors
    ///
    /// Returns [`NativeProtocolError::DeserializationFailed`] if the bytes
    /// are not a valid `MessagePack`-encoded `RelayMessage`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NativeProtocolError> {
        rmp_serde::from_slice(bytes)
            .map_err(|e| NativeProtocolError::DeserializationFailed(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validates a `ref_id` value against the maximum length constraint.
#[allow(clippy::ref_option)]
fn validate_ref_id(ref_id: &Option<String>) -> Result<(), NativeProtocolError> {
    if let Some(id) = ref_id
        && id.len() > MAX_REF_ID_LEN
    {
        return Err(NativeProtocolError::ValidationFailed(format!(
            "ref_id must be at most {MAX_REF_ID_LEN} bytes, got {}",
            id.len()
        )));
    }
    Ok(())
}

/// Validates a `blob_ttl` value against the allowed range.
fn validate_blob_ttl(ttl: u32) -> Result<(), NativeProtocolError> {
    if !(MIN_BLOB_TTL..=MAX_BLOB_TTL).contains(&ttl) {
        return Err(NativeProtocolError::ValidationFailed(format!(
            "blob_ttl must be {MIN_BLOB_TTL}-{MAX_BLOB_TTL}, got {ttl}"
        )));
    }
    Ok(())
}

/// Validates a blob payload against the allowed size range.
fn validate_blob(blob: &[u8]) -> Result<(), NativeProtocolError> {
    if blob.is_empty() || blob.len() > MAX_BLOB_SIZE {
        return Err(NativeProtocolError::ValidationFailed(format!(
            "blob must be 1-{MAX_BLOB_SIZE} bytes, got {}",
            blob.len()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ClientMessage roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn publish_roundtrip() {
        let msg = ClientMessage::Publish {
            ref_id: Some("req-1".to_string()),
            routing_id: [0xAA; 32],
            recipient_hint: Some([0xBB; 32]),
            blob_ttl: 3600,
            blob: vec![0x01, 0x02, 0x03],
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = ClientMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn publish_no_optional_fields_roundtrip() {
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: [0xCC; 32],
            recipient_hint: None,
            blob_ttl: 1,
            blob: vec![0xFF],
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = ClientMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn subscribe_roundtrip() {
        let msg = ClientMessage::Subscribe {
            ref_id: Some("sub-1".to_string()),
            routing_id: [0x11; 32],
            since: Some(1_700_000_000),
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = ClientMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn subscribe_no_since_roundtrip() {
        let msg = ClientMessage::Subscribe {
            ref_id: None,
            routing_id: [0x22; 32],
            since: None,
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = ClientMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn unsubscribe_roundtrip() {
        let msg = ClientMessage::Unsubscribe {
            ref_id: Some("unsub-1".to_string()),
            routing_id: [0x33; 32],
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = ClientMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn query_roundtrip() {
        let msg = ClientMessage::Query {
            ref_id: Some("q-1".to_string()),
            routing_id: [0x44; 32],
            since: Some(1_000_000),
            limit: Some(500),
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = ClientMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn query_no_optional_fields_roundtrip() {
        let msg = ClientMessage::Query {
            ref_id: None,
            routing_id: [0x55; 32],
            since: None,
            limit: None,
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = ClientMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn delete_roundtrip() {
        let msg = ClientMessage::Delete {
            ref_id: Some("del-1".to_string()),
            blob_id: [0x66; 32],
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = ClientMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn ack_roundtrip() {
        let msg = ClientMessage::Ack {
            blob_id: [0x77; 32],
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = ClientMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn ping_roundtrip() {
        let msg = ClientMessage::Ping { ts: 1_700_000_000 };

        let bytes = msg.to_bytes().unwrap();
        let restored = ClientMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn bridge_register_roundtrip() {
        let msg = ClientMessage::BridgeRegister {
            ref_id: Some("br-1".to_string()),
            routing_id: [0xBB; 32],
            public_key: [0xAA; 32],
            signature: [0xCC; 64],
            timestamp: 1_700_000_000,
            target_relay_hint: Some("ws://192.168.1.1:9000/scp/v1".to_string()),
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = ClientMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn bridge_register_no_optional_fields_roundtrip() {
        let msg = ClientMessage::BridgeRegister {
            ref_id: None,
            routing_id: [0xCC; 32],
            public_key: [0xDD; 32],
            signature: [0xEE; 64],
            timestamp: 1_700_000_000,
            target_relay_hint: None,
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = ClientMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn bridge_data_client_roundtrip() {
        let msg = ClientMessage::BridgeData {
            ref_id: Some("bd-1".to_string()),
            target_routing_id: [0xDD; 32],
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = ClientMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    // -----------------------------------------------------------------------
    // RelayMessage roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn ok_with_blob_id_roundtrip() {
        let msg = RelayMessage::Ok {
            ref_id: Some("req-1".to_string()),
            blob_id: Some([0xAA; 32]),
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = RelayMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn ok_without_blob_id_roundtrip() {
        let msg = RelayMessage::Ok {
            ref_id: Some("sub-1".to_string()),
            blob_id: None,
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = RelayMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn ok_no_optional_fields_roundtrip() {
        let msg = RelayMessage::Ok {
            ref_id: None,
            blob_id: None,
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = RelayMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn err_roundtrip() {
        let msg = RelayMessage::Err {
            ref_id: Some("req-2".to_string()),
            code: 4010,
            msg: "blob exceeds maximum size".to_string(),
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = RelayMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn err_no_ref_roundtrip() {
        let msg = RelayMessage::Err {
            ref_id: None,
            code: 5000,
            msg: "internal error".to_string(),
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = RelayMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn blob_roundtrip() {
        let msg = RelayMessage::Blob {
            routing_id: [0x11; 32],
            blob_id: [0x22; 32],
            recipient_hint: Some([0x33; 32]),
            blob_ttl: 7200,
            stored_at: 1_700_000_000,
            blob: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = RelayMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn blob_no_recipient_hint_roundtrip() {
        let msg = RelayMessage::Blob {
            routing_id: [0x44; 32],
            blob_id: [0x55; 32],
            recipient_hint: None,
            blob_ttl: 60,
            stored_at: 1_700_000_001,
            blob: vec![0x01],
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = RelayMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn event_roundtrip() {
        let msg = RelayMessage::Event {
            ref_id: Some("sub-1".to_string()),
            event_type: "backfill_complete".to_string(),
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = RelayMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn event_query_complete_roundtrip() {
        let msg = RelayMessage::Event {
            ref_id: Some("q-1".to_string()),
            event_type: "query_complete".to_string(),
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = RelayMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn pong_roundtrip() {
        let msg = RelayMessage::Pong { ts: 1_700_000_000 };

        let bytes = msg.to_bytes().unwrap();
        let restored = RelayMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn bridge_data_relay_roundtrip() {
        let msg = RelayMessage::BridgeData {
            source_routing_id: [0xEE; 32],
            payload: vec![0x01, 0x02, 0x03, 0x04],
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = RelayMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    // -----------------------------------------------------------------------
    // Binary encoding verification
    // -----------------------------------------------------------------------

    #[test]
    fn routing_id_serialized_as_binary_not_array() {
        // When serialized via serde_bytes, [u8; 32] should produce a
        // MessagePack bin header, not an array of 32 integers.
        // Test with Subscribe which has a routing_id field.
        let msg = ClientMessage::Subscribe {
            ref_id: None,
            routing_id: [0xAA; 32],
            since: None,
        };
        let bytes = msg.to_bytes().unwrap();

        // The serialized bytes should contain the raw 0xAA bytes as a binary
        // blob. MessagePack bin32 header is 0xC6, bin8 is 0xC4. For 32 bytes,
        // rmp-serde uses bin8 (0xC4, length=0x20).
        // Verify the 32-byte sequence exists contiguously in the output.
        let needle = [0xAA; 32];
        let found = bytes.windows(32).any(|window| window == needle);
        assert!(
            found,
            "routing_id bytes should appear contiguously as binary"
        );

        // Also verify that the deserialized message matches.
        let restored = ClientMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    // -----------------------------------------------------------------------
    // Forward compatibility (unknown fields ignored)
    // -----------------------------------------------------------------------

    #[test]
    fn unknown_fields_ignored_on_deserialization() {
        // Serialize a PING message, then manually inject an unknown field
        // and verify deserialization still succeeds.
        // Build a MessagePack map with op=PING, ts=42, and unknown="ignored".
        let mut map = std::collections::BTreeMap::new();
        map.insert("op".to_string(), rmpv::Value::String("PING".into()));
        map.insert("ts".to_string(), rmpv::Value::Integer(42.into()));
        map.insert(
            "unknown_field".to_string(),
            rmpv::Value::String("should be ignored".into()),
        );

        let bytes = rmp_serde::to_vec_named(&map).unwrap();
        let msg = ClientMessage::from_bytes(&bytes).unwrap();

        assert_eq!(msg, ClientMessage::Ping { ts: 42 });
    }

    #[test]
    fn unknown_fields_ignored_on_relay_message() {
        let mut map = std::collections::BTreeMap::new();
        map.insert("op".to_string(), rmpv::Value::String("PONG".into()));
        map.insert("ts".to_string(), rmpv::Value::Integer(99.into()));
        map.insert("extra".to_string(), rmpv::Value::Boolean(true));

        let bytes = rmp_serde::to_vec_named(&map).unwrap();
        let msg = RelayMessage::from_bytes(&bytes).unwrap();

        assert_eq!(msg, RelayMessage::Pong { ts: 99 });
    }

    // -----------------------------------------------------------------------
    // Validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_publish_valid() {
        let msg = ClientMessage::Publish {
            ref_id: Some("ok".to_string()),
            routing_id: [0x00; 32],
            recipient_hint: None,
            blob_ttl: 3600,
            blob: vec![0x01],
        };
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn validate_publish_blob_too_large() {
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: [0x00; 32],
            recipient_hint: None,
            blob_ttl: 60,
            blob: vec![0x00; MAX_BLOB_SIZE + 1],
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("blob must be"));
    }

    #[test]
    fn validate_publish_blob_empty() {
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: [0x00; 32],
            recipient_hint: None,
            blob_ttl: 60,
            blob: vec![],
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("blob must be"));
    }

    #[test]
    fn validate_publish_ttl_zero() {
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: [0x00; 32],
            recipient_hint: None,
            blob_ttl: 0,
            blob: vec![0x01],
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("blob_ttl"));
    }

    #[test]
    fn validate_publish_ttl_too_long() {
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: [0x00; 32],
            recipient_hint: None,
            blob_ttl: MAX_BLOB_TTL + 1,
            blob: vec![0x01],
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("blob_ttl"));
    }

    #[test]
    fn validate_publish_ttl_boundary_values() {
        // Minimum valid TTL
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: [0x00; 32],
            recipient_hint: None,
            blob_ttl: MIN_BLOB_TTL,
            blob: vec![0x01],
        };
        assert!(msg.validate().is_ok());

        // Maximum valid TTL
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: [0x00; 32],
            recipient_hint: None,
            blob_ttl: MAX_BLOB_TTL,
            blob: vec![0x01],
        };
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn validate_publish_ref_id_too_long() {
        let msg = ClientMessage::Publish {
            ref_id: Some("x".repeat(MAX_REF_ID_LEN + 1)),
            routing_id: [0x00; 32],
            recipient_hint: None,
            blob_ttl: 60,
            blob: vec![0x01],
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("ref_id"));
    }

    #[test]
    fn validate_publish_ref_id_at_max_length() {
        let msg = ClientMessage::Publish {
            ref_id: Some("x".repeat(MAX_REF_ID_LEN)),
            routing_id: [0x00; 32],
            recipient_hint: None,
            blob_ttl: 60,
            blob: vec![0x01],
        };
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn validate_query_limit_too_high() {
        let msg = ClientMessage::Query {
            ref_id: None,
            routing_id: [0x00; 32],
            since: None,
            limit: Some(MAX_QUERY_LIMIT + 1),
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("limit"));
    }

    #[test]
    fn validate_query_limit_zero() {
        let msg = ClientMessage::Query {
            ref_id: None,
            routing_id: [0x00; 32],
            since: None,
            limit: Some(0),
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("limit"));
    }

    #[test]
    fn validate_query_limit_at_max() {
        let msg = ClientMessage::Query {
            ref_id: None,
            routing_id: [0x00; 32],
            since: None,
            limit: Some(MAX_QUERY_LIMIT),
        };
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn validate_query_limit_none_is_valid() {
        let msg = ClientMessage::Query {
            ref_id: None,
            routing_id: [0x00; 32],
            since: None,
            limit: None,
        };
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn validate_subscribe_ref_id_too_long() {
        let msg = ClientMessage::Subscribe {
            ref_id: Some("x".repeat(MAX_REF_ID_LEN + 1)),
            routing_id: [0x00; 32],
            since: None,
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("ref_id"));
    }

    #[test]
    fn validate_ack_always_valid() {
        let msg = ClientMessage::Ack {
            blob_id: [0x00; 32],
        };
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn validate_ping_always_valid() {
        let msg = ClientMessage::Ping { ts: 0 };
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn validate_bridge_register_valid() {
        let msg = ClientMessage::BridgeRegister {
            ref_id: Some("br-1".to_string()),
            routing_id: [0x00; 32],
            public_key: [0xAA; 32],
            signature: [0xBB; 64],
            timestamp: 1_700_000_000,
            target_relay_hint: Some("ws://192.168.1.1:9000/scp/v1".to_string()),
        };
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn validate_bridge_register_ref_id_too_long() {
        let msg = ClientMessage::BridgeRegister {
            ref_id: Some("x".repeat(MAX_REF_ID_LEN + 1)),
            routing_id: [0x00; 32],
            public_key: [0xAA; 32],
            signature: [0xBB; 64],
            timestamp: 1_700_000_000,
            target_relay_hint: None,
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("ref_id"));
    }

    #[test]
    fn validate_bridge_data_valid() {
        let msg = ClientMessage::BridgeData {
            ref_id: None,
            target_routing_id: [0x00; 32],
            payload: vec![0x01, 0x02],
        };
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn validate_bridge_data_empty_payload() {
        let msg = ClientMessage::BridgeData {
            ref_id: None,
            target_routing_id: [0x00; 32],
            payload: vec![],
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("bridge payload"));
    }

    #[test]
    fn validate_bridge_data_payload_too_large() {
        let msg = ClientMessage::BridgeData {
            ref_id: None,
            target_routing_id: [0x00; 32],
            payload: vec![0x00; MAX_BLOB_SIZE + 1],
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("bridge payload"));
    }

    // -----------------------------------------------------------------------
    // Op field serialization
    // -----------------------------------------------------------------------

    #[test]
    fn client_message_op_field_is_string() {
        // Verify the "op" field appears in the serialized bytes as a
        // MessagePack string, not an integer.
        let msg = ClientMessage::Ping { ts: 1 };
        let bytes = msg.to_bytes().unwrap();

        // Deserialize to a generic map and check the op field.
        let map: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).unwrap();
        let op = map.get("op").unwrap();
        assert_eq!(op.as_str(), Some("PING"));
    }

    #[test]
    fn relay_message_op_field_is_string() {
        let msg = RelayMessage::Pong { ts: 1 };
        let bytes = msg.to_bytes().unwrap();

        let map: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).unwrap();
        let op = map.get("op").unwrap();
        assert_eq!(op.as_str(), Some("PONG"));
    }

    #[test]
    fn all_client_ops_have_correct_names() {
        let cases: Vec<(ClientMessage, &str)> = vec![
            (
                ClientMessage::Publish {
                    ref_id: None,
                    routing_id: [0; 32],
                    recipient_hint: None,
                    blob_ttl: 1,
                    blob: vec![0x01],
                },
                "PUBLISH",
            ),
            (
                ClientMessage::Subscribe {
                    ref_id: None,
                    routing_id: [0; 32],
                    since: None,
                },
                "SUBSCRIBE",
            ),
            (
                ClientMessage::Unsubscribe {
                    ref_id: None,
                    routing_id: [0; 32],
                },
                "UNSUBSCRIBE",
            ),
            (
                ClientMessage::Query {
                    ref_id: None,
                    routing_id: [0; 32],
                    since: None,
                    limit: None,
                },
                "QUERY",
            ),
            (
                ClientMessage::Delete {
                    ref_id: None,
                    blob_id: [0; 32],
                },
                "DELETE",
            ),
            (ClientMessage::Ack { blob_id: [0; 32] }, "ACK"),
            (ClientMessage::Ping { ts: 0 }, "PING"),
            (
                ClientMessage::BridgeRegister {
                    ref_id: None,
                    routing_id: [0; 32],
                    public_key: [0; 32],
                    signature: [0; 64],
                    timestamp: 0,
                    target_relay_hint: None,
                },
                "BRIDGE_REGISTER",
            ),
            (
                ClientMessage::BridgeData {
                    ref_id: None,
                    target_routing_id: [0; 32],
                    payload: vec![0x01],
                },
                "BRIDGE_DATA",
            ),
        ];

        for (msg, expected_op) in cases {
            let bytes = msg.to_bytes().unwrap();
            let map: std::collections::BTreeMap<String, rmpv::Value> =
                rmp_serde::from_slice(&bytes).unwrap();
            let op = map.get("op").unwrap().as_str().unwrap();
            assert_eq!(op, expected_op, "wrong op for {msg:?}");
        }
    }

    #[test]
    fn all_relay_ops_have_correct_names() {
        let cases: Vec<(RelayMessage, &str)> = vec![
            (
                RelayMessage::Ok {
                    ref_id: None,
                    blob_id: None,
                },
                "OK",
            ),
            (
                RelayMessage::Err {
                    ref_id: None,
                    code: 4000,
                    msg: "test".to_string(),
                },
                "ERR",
            ),
            (
                RelayMessage::Blob {
                    routing_id: [0; 32],
                    blob_id: [0; 32],
                    recipient_hint: None,
                    blob_ttl: 1,
                    stored_at: 0,
                    blob: vec![0x01],
                },
                "BLOB",
            ),
            (
                RelayMessage::Event {
                    ref_id: None,
                    event_type: "test".to_string(),
                },
                "EVENT",
            ),
            (RelayMessage::Pong { ts: 0 }, "PONG"),
            (
                RelayMessage::BridgeData {
                    source_routing_id: [0; 32],
                    payload: vec![0x01],
                },
                "BRIDGE_DATA",
            ),
        ];

        for (msg, expected_op) in cases {
            let bytes = msg.to_bytes().unwrap();
            let map: std::collections::BTreeMap<String, rmpv::Value> =
                rmp_serde::from_slice(&bytes).unwrap();
            let op = map.get("op").unwrap().as_str().unwrap();
            assert_eq!(op, expected_op, "wrong op for {msg:?}");
        }
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn constants_match_specification() {
        assert_eq!(MAX_BLOB_SIZE, 262_144);
        assert_eq!(MIN_BLOB_TTL, 1);
        assert_eq!(MAX_BLOB_TTL, 604_800);
        assert_eq!(MAX_REF_ID_LEN, 64);
        assert_eq!(DEFAULT_QUERY_LIMIT, 100);
        assert_eq!(MAX_QUERY_LIMIT, 1000);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn publish_max_blob_size_roundtrip() {
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: [0x00; 32],
            recipient_hint: None,
            blob_ttl: 60,
            blob: vec![0xAB; MAX_BLOB_SIZE],
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = ClientMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn deserialize_invalid_bytes_returns_error() {
        let garbage = vec![0xFF, 0xFE, 0xFD];
        let result = ClientMessage::from_bytes(&garbage);
        assert!(result.is_err());

        let result = RelayMessage::from_bytes(&garbage);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_empty_bytes_returns_error() {
        let result = ClientMessage::from_bytes(&[]);
        assert!(result.is_err());

        let result = RelayMessage::from_bytes(&[]);
        assert!(result.is_err());
    }
}
