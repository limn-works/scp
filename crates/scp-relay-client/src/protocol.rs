//! Relay wire protocol message types and `MessagePack` wire format (shared by
//! the native relay and the in-browser client).
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

use scp_protocol::node::NODE_PROOF_LEN;
use serde::{Deserialize, Serialize};

use super::error::{RelayProtocolError, code};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum blob size in bytes (256 KB).
pub const MAX_BLOB_SIZE: usize = 262_144;

/// Minimum blob TTL in seconds (1 second).
pub const MIN_BLOB_TTL: u32 = 1;

/// Maximum blob TTL in seconds (7 days).
pub const MAX_BLOB_TTL: u32 = 604_800;

// A member requests the relay maximum for every MLS message it publishes other
// than a heartbeat or a checkpoint, whose shorter TTLs a relay must also accept
// (`09-security-model.md` §9.10.2 "Blob TTL by message type"). The values live
// in `scp-protocol`, which cannot depend on this crate, so the relations are
// pinned here: changing a constant alone fails the build.
const _: () = assert!(
    scp_protocol::envelope::outer::DEFAULT_APP_DATA_BLOB_TTL_SECS == MAX_BLOB_TTL,
    "DEFAULT_APP_DATA_BLOB_TTL_SECS must equal MAX_BLOB_TTL (spec 09 §9.10.2)"
);
const _: () = assert!(
    scp_protocol::envelope::outer::HEARTBEAT_BLOB_TTL_SECS >= MIN_BLOB_TTL
        && scp_protocol::envelope::outer::HEARTBEAT_BLOB_TTL_SECS <= MAX_BLOB_TTL,
    "HEARTBEAT_BLOB_TTL_SECS must lie in [MIN_BLOB_TTL, MAX_BLOB_TTL] (spec 09 §9.10.2)"
);
const _: () = assert!(
    scp_protocol::envelope::outer::CHECKPOINT_BLOB_TTL_SECS >= MIN_BLOB_TTL
        && scp_protocol::envelope::outer::CHECKPOINT_BLOB_TTL_SECS <= MAX_BLOB_TTL,
    "CHECKPOINT_BLOB_TTL_SECS must lie in [MIN_BLOB_TTL, MAX_BLOB_TTL] (spec 09 §9.10.2)"
);

/// Maximum `ref_id` length in bytes.
pub const MAX_REF_ID_LEN: usize = 64;

/// Default QUERY limit when not specified.
pub const DEFAULT_QUERY_LIMIT: u32 = 100;

/// Maximum QUERY limit.
pub const MAX_QUERY_LIMIT: u32 = 1000;

/// Maximum size of a `ClientMessage` or `RelayMessage` in bytes (1 MiB).
///
/// Pre-deserialization guard against allocation bombs from malformed
/// `MessagePack` input.
pub const MAX_MESSAGE_SIZE: usize = 1_048_576;

// ---------------------------------------------------------------------------
// PUBLISH lifetime
// ---------------------------------------------------------------------------

/// A PUBLISH `blob_ttl` in seconds, always within
/// `MIN_BLOB_TTL..=MAX_BLOB_TTL` (`09-security-model.md` §9.10.12, ADR-004
/// operation 1).
///
/// The field is private. [`new`](Self::new) refuses a value outside the range
/// with [`LifetimeError::TtlOutOfRange`] (`4011`), and decoding goes through
/// it, so no `PublishTtl` holds an out-of-range value and no seam checks one
/// again. [`of`](Self::of) builds a literal with the range checked at compile
/// time:
///
/// ```
/// use scp_relay_client::{MAX_BLOB_TTL, PublishTtl};
/// assert_eq!(PublishTtl::of::<3600>().secs(), 3600);
/// assert_eq!(PublishTtl::new(MAX_BLOB_TTL).map(PublishTtl::secs), Ok(MAX_BLOB_TTL));
/// ```
///
/// A literal outside the range does not build:
///
/// ```compile_fail,E0080
/// let _ = scp_relay_client::PublishTtl::of::<0>();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct PublishTtl(u32);

impl PublishTtl {
    /// The shortest TTL, [`MIN_BLOB_TTL`].
    pub const MIN: Self = Self::of::<MIN_BLOB_TTL>();

    /// The longest TTL, [`MAX_BLOB_TTL`].
    pub const MAX: Self = Self::of::<MAX_BLOB_TTL>();

    /// The TTL of `secs` seconds.
    ///
    /// # Errors
    ///
    /// [`LifetimeError::TtlOutOfRange`] for `secs` outside
    /// `MIN_BLOB_TTL..=MAX_BLOB_TTL`.
    pub const fn new(secs: u32) -> Result<Self, LifetimeError> {
        if secs < MIN_BLOB_TTL || secs > MAX_BLOB_TTL {
            return Err(LifetimeError::TtlOutOfRange(secs));
        }
        Ok(Self(secs))
    }

    /// The TTL of the literal `SECS` seconds; an out-of-range `SECS` fails
    /// the build.
    #[must_use]
    pub const fn of<const SECS: u32>() -> Self {
        const {
            assert!(
                SECS >= MIN_BLOB_TTL && SECS <= MAX_BLOB_TTL,
                "a PUBLISH blob_ttl lies in MIN_BLOB_TTL..=MAX_BLOB_TTL"
            );
        }
        Self(SECS)
    }

    /// The TTL in seconds.
    #[must_use]
    pub const fn secs(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for PublishTtl {
    type Error = LifetimeError;

    fn try_from(secs: u32) -> Result<Self, LifetimeError> {
        Self::new(secs)
    }
}

impl From<PublishTtl> for u32 {
    fn from(ttl: PublishTtl) -> Self {
        ttl.0
    }
}

/// How long a node keeps a published blob, the one choice a PUBLISH makes
/// between the shared TTL and retention (`09-security-model.md` §9.10.12,
/// ADR-004 operation 1).
///
/// On the wire it is the two §9.10.12 keys: `blob_ttl: <seconds>` for
/// [`Ttl`](Self::Ttl), `retain: true` for [`Retained`](Self::Retained). A
/// decoder refuses a PUBLISH that carries both keys, neither key,
/// `retain: false`, or a `blob_ttl` outside `MIN_BLOB_TTL..=MAX_BLOB_TTL`
/// ([`LifetimeError`]), so no decoded PUBLISH holds a combination §9.10.12
/// forbids. A `Ttl` holds a [`PublishTtl`], so a raw integer does not build
/// one:
///
/// ```compile_fail,E0308
/// let _ = scp_relay_client::BlobLifetime::Ttl(0);
/// ```
///
/// ```
/// use scp_relay_client::{BlobLifetime, PublishTtl};
/// let _ = BlobLifetime::Ttl(PublishTtl::of::<60>());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "LifetimeFields", into = "LifetimeFields")]
pub enum BlobLifetime {
    /// Stored under the shared TTL.
    Ttl(PublishTtl),
    /// A record of a retained kind (`scp:did:`, `scp:svc:`, `scp:wit:`,
    /// `scp:wcf:`, `scp:nls:`), kept with no TTL.
    Retained,
}

impl BlobLifetime {
    /// The lifetime a PUBLISH's `retain` and `blob_ttl` keys declare.
    ///
    /// # Errors
    ///
    /// [`LifetimeError`] for both keys, neither key, `retain: false`, or a
    /// `blob_ttl` outside `MIN_BLOB_TTL..=MAX_BLOB_TTL`.
    pub const fn from_fields(
        retain: Option<bool>,
        blob_ttl: Option<u32>,
    ) -> Result<Self, LifetimeError> {
        match (retain, blob_ttl) {
            (Some(true), None) => Ok(Self::Retained),
            (Some(true), Some(_)) => Err(LifetimeError::Both),
            (Some(false), _) => Err(LifetimeError::RetainFalse),
            (None, None) => Err(LifetimeError::Neither),
            (None, Some(secs)) => match PublishTtl::new(secs) {
                Ok(ttl) => Ok(Self::Ttl(ttl)),
                Err(error) => Err(error),
            },
        }
    }

    /// The TTL; `None` for a retained record.
    #[must_use]
    pub const fn ttl(self) -> Option<PublishTtl> {
        match self {
            Self::Ttl(ttl) => Some(ttl),
            Self::Retained => None,
        }
    }
}

/// Why a PUBLISH's lifetime keys name no [`BlobLifetime`]
/// (`09-security-model.md` §9.10.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LifetimeError {
    /// `retain` and `blob_ttl` both present.
    #[error("a PUBLISH carries retain or blob_ttl, never both")]
    Both,
    /// Neither `retain` nor `blob_ttl` present.
    #[error("a PUBLISH carries retain or blob_ttl")]
    Neither,
    /// `retain: false`; the key is present only as `true`.
    #[error("retain is true or absent")]
    RetainFalse,
    /// A `blob_ttl` outside `MIN_BLOB_TTL..=MAX_BLOB_TTL`.
    #[error("blob_ttl must be {MIN_BLOB_TTL}-{MAX_BLOB_TTL}, got {0}")]
    TtlOutOfRange(u32),
}

impl LifetimeError {
    /// The ADR-004 error code a relay answers with: `4003` for both keys or
    /// `retain: false`, `4002` for neither, `4011` for an out-of-range TTL.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Both | Self::RetainFalse => code::INVALID_FIELD,
            Self::Neither => code::MISSING_FIELD,
            Self::TtlOutOfRange(_) => code::TTL_TOO_LONG,
        }
    }
}

/// The two wire keys [`BlobLifetime`] maps to; never a public value.
#[derive(Serialize, Deserialize)]
struct LifetimeFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blob_ttl: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retain: Option<bool>,
}

impl TryFrom<LifetimeFields> for BlobLifetime {
    type Error = LifetimeError;

    fn try_from(fields: LifetimeFields) -> Result<Self, LifetimeError> {
        Self::from_fields(fields.retain, fields.blob_ttl)
    }
}

impl From<BlobLifetime> for LifetimeFields {
    fn from(lifetime: BlobLifetime) -> Self {
        match lifetime {
            BlobLifetime::Ttl(ttl) => Self {
                blob_ttl: Some(ttl.secs()),
                retain: None,
            },
            BlobLifetime::Retained => Self {
                blob_ttl: None,
                retain: Some(true),
            },
        }
    }
}

/// The lifetime refusal a PUBLISH that failed to decode carries, if that is
/// why it failed: the frame decodes as a map with `op: "PUBLISH"` whose
/// lifetime keys name no [`BlobLifetime`].
fn lifetime_refusal(bytes: &[u8]) -> Option<RelayProtocolError> {
    #[derive(Deserialize)]
    struct Probe {
        op: String,
        #[serde(rename = "ref", default)]
        ref_id: Option<String>,
        #[serde(default)]
        retain: Option<bool>,
        #[serde(default)]
        blob_ttl: Option<u32>,
    }
    let probe: Probe = rmp_serde::from_slice(bytes).ok()?;
    if probe.op != "PUBLISH" {
        return None;
    }
    let error = BlobLifetime::from_fields(probe.retain, probe.blob_ttl).err()?;
    Some(RelayProtocolError::Lifetime {
        // An over-long `ref` is not echoed; the reply carries none.
        ref_id: probe.ref_id.filter(|id| id.len() <= MAX_REF_ID_LEN),
        error,
    })
}

// ---------------------------------------------------------------------------
// Serde helper for Option<[u8; 32]> as MessagePack binary
// ---------------------------------------------------------------------------

/// Serde for an optional fixed-width byte field carried as `MessagePack` `bin`
/// (never an array of integers) of exactly `N` bytes: 32 for a routing id,
/// blob id or nonce, 200 for a node proof (`09-security-model.md` §9.7.4.2
/// definitions). A width other than `N` is refused.
mod byte_array_opt {
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    /// A field of exactly `N` bytes, held inline or boxed. A 200-byte node
    /// proof is boxed so that every `RelayMessage` does not carry it inline.
    pub trait FixedBytes: Sized {
        fn bytes(&self) -> &[u8];
        fn from_vec(bytes: Vec<u8>) -> Result<Self, Vec<u8>>;
    }

    impl<const N: usize> FixedBytes for [u8; N] {
        fn bytes(&self) -> &[u8] {
            self
        }
        fn from_vec(bytes: Vec<u8>) -> Result<Self, Vec<u8>> {
            bytes.try_into()
        }
    }

    impl<const N: usize> FixedBytes for Box<[u8; N]> {
        fn bytes(&self) -> &[u8] {
            self.as_slice()
        }
        fn from_vec(bytes: Vec<u8>) -> Result<Self, Vec<u8>> {
            <[u8; N]>::from_vec(bytes).map(Self::new)
        }
    }

    // serde Serialize signature requires &Option<T>.
    #[allow(clippy::ref_option)]
    pub fn serialize<T: FixedBytes, S: Serializer>(
        value: &Option<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(arr) => serializer.serialize_bytes(arr.bytes()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, T: FixedBytes, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<T>, D::Error> {
        let opt: Option<serde_bytes::ByteBuf> = serde::Deserialize::deserialize(deserializer)?;
        opt.map(|buf| {
            T::from_vec(buf.into_vec()).map_err(|v: Vec<u8>| {
                D::Error::custom(format!("expected a fixed-width bin, got {} bytes", v.len()))
            })
        })
        .transpose()
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
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// Per-context pseudonym for routing (32 bytes).
        #[serde(with = "serde_bytes")]
        routing_id: [u8; 32],

        /// Optional recipient pseudonym for directed delivery (32 bytes).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "byte_array_opt"
        )]
        recipient_hint: Option<[u8; 32]>,

        /// The shared TTL or retention, on the wire as `blob_ttl` or
        /// `retain: true` (`09-security-model.md` §9.10.12).
        #[serde(flatten)]
        lifetime: BlobLifetime,

        /// The opaque blob content. 1--262144 bytes (256 KB).
        /// Bounded to 512 KiB on deserialization to prevent OOM (#347).
        #[serde(with = "scp_protocol::serde_util::serde_bounded_bytes")]
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
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
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
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
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
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// Per-context pseudonym to query (32 bytes).
        #[serde(with = "serde_bytes")]
        routing_id: [u8; 32],

        /// Optional unix timestamp; return only blobs newer than this.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since: Option<u64>,

        /// The page-walk cursor: with it, the node returns only the blobs
        /// whose pair (`stored_at`, `blob_id`) sorts strictly after the pair
        /// (`since`, `after_blob`). It requires `since` (ADR-004 operation 4;
        /// `09-security-model.md` §9.7.4.2 R9).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "byte_array_opt"
        )]
        after_blob: Option<[u8; 32]>,

        /// Maximum number of blobs to return. Default 100, max 1000.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,

        /// 32 bytes the resolver drew freshly for this query. A listed node
        /// that can sign under the node key its node-list entry binds
        /// answers it with a `node_proof` on the `query_complete` EVENT
        /// (ADR-004 operation 4; `09-security-model.md` §9.10.12).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "byte_array_opt"
        )]
        proof_nonce: Option<[u8; 32]>,
    },

    /// Request deletion of a blob by its ID.
    ///
    /// Best-effort: the relay is untrusted and may not comply.
    #[serde(rename = "DELETE")]
    Delete {
        /// Client-assigned request ID.
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
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
    /// covers `"SCP-BRIDGE-REGISTER-V1:" || routing_id || timestamp`
    /// (domain-separated payload: 23-byte prefix + 32-byte routing ID +
    /// 8-byte big-endian timestamp = 63 bytes). The relay responds with
    /// `OK` on success, `ERR` with code `BRIDGE_AUTH_FAILED` (4034) if
    /// authentication fails, or `ERR` with `BRIDGE_NOT_SUPPORTED` (4030)
    /// if bridging is not enabled.
    #[serde(rename = "BRIDGE_REGISTER")]
    BridgeRegister {
        /// Client-assigned request ID.
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// The routing ID to register for bridge proxying (32 bytes).
        #[serde(with = "serde_bytes")]
        routing_id: [u8; 32],

        /// Ed25519 public key of the DID owner (32 bytes). The relay derives
        /// the DID string from this key and verifies that
        /// `SHA-256("scp:did:" || did_string) == routing_id` (SCP-247).
        #[serde(with = "serde_bytes")]
        public_key: [u8; 32],

        /// Ed25519 signature over `"SCP-BRIDGE-REGISTER-V1:" || routing_id || timestamp`
        /// (64 bytes). Proves the sender holds the private key for `public_key` (SCP-247).
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
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// The routing ID of the target self-hosted relay (32 bytes).
        #[serde(with = "serde_bytes")]
        target_routing_id: [u8; 32],

        /// Opaque payload to forward. The bridge does NOT inspect this.
        /// Bounded to 512 KiB on deserialization to prevent OOM (#347).
        #[serde(with = "scp_protocol::serde_util::serde_bounded_bytes")]
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
    /// Returns [`RelayProtocolError::SerializationFailed`] if serialization
    /// fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RelayProtocolError> {
        rmp_serde::to_vec_named(self)
            .map_err(|e| RelayProtocolError::SerializationFailed(e.to_string()))
    }

    /// Deserializes a `ClientMessage` from `MessagePack` binary format.
    ///
    /// Unknown fields are silently ignored for forward compatibility.
    ///
    /// # Errors
    ///
    /// Returns [`RelayProtocolError::MessageTooLarge`] if `bytes.len()` exceeds
    /// [`MAX_MESSAGE_SIZE`].
    /// Returns [`RelayProtocolError::DeserializationFailed`] if the bytes are
    /// not a valid `MessagePack`-encoded `ClientMessage`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RelayProtocolError> {
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(RelayProtocolError::MessageTooLarge {
                size: bytes.len(),
                max: MAX_MESSAGE_SIZE,
            });
        }
        rmp_serde::from_slice(bytes).map_err(|e| {
            lifetime_refusal(bytes)
                .unwrap_or_else(|| RelayProtocolError::DeserializationFailed(e.to_string()))
        })
    }

    /// Validates this message against protocol constraints.
    ///
    /// Checks:
    /// - `ref_id` length (max 64 bytes)
    /// - `blob` size (1--262144 bytes)
    /// - `limit` range (1--1000)
    ///
    /// A PUBLISH `blob_ttl` needs no check: [`PublishTtl`] holds only an
    /// in-range value.
    ///
    /// # Errors
    ///
    /// Returns [`RelayProtocolError::ValidationFailed`] describing the first
    /// constraint violation found.
    pub fn validate(&self) -> Result<(), RelayProtocolError> {
        match self {
            Self::Publish { ref_id, blob, .. } => {
                validate_ref_id(ref_id)?;
                validate_blob(blob)?;
            }
            Self::Subscribe { ref_id, .. }
            | Self::Unsubscribe { ref_id, .. }
            | Self::Delete { ref_id, .. }
            | Self::BridgeRegister { ref_id, .. } => {
                validate_ref_id(ref_id)?;
            }
            Self::Query {
                ref_id,
                limit,
                since,
                after_blob,
                ..
            } => {
                validate_ref_id(ref_id)?;
                if after_blob.is_some() && since.is_none() {
                    return Err(RelayProtocolError::ValidationFailed(
                        "after_blob requires since".into(),
                    ));
                }
                if let Some(l) = limit
                    && (*l == 0 || *l > MAX_QUERY_LIMIT)
                {
                    return Err(RelayProtocolError::ValidationFailed(format!(
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
                    return Err(RelayProtocolError::ValidationFailed(format!(
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
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// Blob identifier (present only for PUBLISH responses).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "byte_array_opt"
        )]
        blob_id: Option<[u8; 32]>,
    },

    /// Error response with a numeric code and human-readable message.
    ///
    /// The `msg` field is for logging only -- clients MUST NOT parse it.
    /// Use [`code::is_client_error`](crate::code::is_client_error) and
    /// [`code::is_server_error`](crate::code::is_server_error) to
    /// determine retry strategy.
    #[serde(rename = "ERR")]
    Err {
        /// Echoed client request ID.
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
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
            with = "byte_array_opt"
        )]
        recipient_hint: Option<[u8; 32]>,

        /// TTL at time of storage (seconds); absent on a retained record,
        /// which carries none (ADR-004, `09-security-model.md` §9.10.12).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blob_ttl: Option<u32>,

        /// Unix timestamp when the relay stored the blob.
        stored_at: u64,

        /// The opaque blob content.
        /// Bounded to 512 KiB on deserialization to prevent OOM (#347).
        #[serde(with = "scp_protocol::serde_util::serde_bounded_bytes")]
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
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        ref_id: Option<String>,

        /// Event type identifier (e.g., `"backfill_complete"`,
        /// `"query_complete"`).
        #[serde(rename = "type")]
        event_type: String,

        /// On `query_complete`: the 200-byte node proof of control over
        /// this response, present where the QUERY carried a `proof_nonce`
        /// and the node holds a bound node key (ADR-004 `EVENT`;
        /// `09-security-model.md` §9.7.4.2 definitions, §9.10.12).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "byte_array_opt"
        )]
        node_proof: Option<Box<[u8; NODE_PROOF_LEN]>>,
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
    /// Returns [`RelayProtocolError::SerializationFailed`] if serialization
    /// fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RelayProtocolError> {
        rmp_serde::to_vec_named(self)
            .map_err(|e| RelayProtocolError::SerializationFailed(e.to_string()))
    }

    /// Deserializes a `RelayMessage` from `MessagePack` binary format.
    ///
    /// Unknown fields are silently ignored for forward compatibility.
    ///
    /// # Errors
    ///
    /// Returns [`RelayProtocolError::MessageTooLarge`] if `bytes.len()` exceeds
    /// [`MAX_MESSAGE_SIZE`].
    /// Returns [`RelayProtocolError::DeserializationFailed`] if the bytes are
    /// not a valid `MessagePack`-encoded `RelayMessage`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RelayProtocolError> {
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(RelayProtocolError::MessageTooLarge {
                size: bytes.len(),
                max: MAX_MESSAGE_SIZE,
            });
        }
        rmp_serde::from_slice(bytes)
            .map_err(|e| RelayProtocolError::DeserializationFailed(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validates a `ref_id` value against the maximum length constraint.
#[allow(clippy::ref_option)]
fn validate_ref_id(ref_id: &Option<String>) -> Result<(), RelayProtocolError> {
    if let Some(id) = ref_id
        && id.len() > MAX_REF_ID_LEN
    {
        return Err(RelayProtocolError::ValidationFailed(format!(
            "ref_id must be at most {MAX_REF_ID_LEN} bytes, got {}",
            id.len()
        )));
    }
    Ok(())
}

/// Validates a blob payload against the allowed size range.
fn validate_blob(blob: &[u8]) -> Result<(), RelayProtocolError> {
    if blob.is_empty() || blob.len() > MAX_BLOB_SIZE {
        return Err(RelayProtocolError::ValidationFailed(format!(
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

    /// A member's MLS-message TTL is the relay maximum
    /// (`09-security-model.md` §9.10.2 "Blob TTL by message type"), and a
    /// PUBLISH carrying it passes the decode-side TTL bound.
    #[test]
    fn app_data_blob_ttl_is_the_relay_maximum_and_decodes() {
        let ttl = scp_protocol::envelope::outer::DEFAULT_APP_DATA_BLOB_TTL_SECS;
        assert_eq!(ttl, MAX_BLOB_TTL);
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: [0xAA; 32],
            recipient_hint: None,
            lifetime: BlobLifetime::Ttl(PublishTtl::new(ttl).unwrap()),
            blob: vec![0x01],
        };
        let decoded = ClientMessage::from_bytes(&msg.to_bytes().unwrap()).unwrap();
        assert_eq!(decoded, msg);
    }

    // -----------------------------------------------------------------------
    // ClientMessage roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn publish_roundtrip() {
        let msg = ClientMessage::Publish {
            ref_id: Some("req-1".to_string()),
            routing_id: [0xAA; 32],
            recipient_hint: Some([0xBB; 32]),
            lifetime: BlobLifetime::Ttl(PublishTtl::of::<3600>()),
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
            lifetime: BlobLifetime::Ttl(PublishTtl::of::<1>()),
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
            proof_nonce: None,
            ref_id: Some("q-1".to_string()),
            routing_id: [0x44; 32],
            since: Some(1_000_000),
            after_blob: None,
            limit: Some(500),
        };

        let bytes = msg.to_bytes().unwrap();
        let restored = ClientMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, restored);
    }

    #[test]
    fn query_no_optional_fields_roundtrip() {
        let msg = ClientMessage::Query {
            proof_nonce: None,
            ref_id: None,
            routing_id: [0x55; 32],
            since: None,
            after_blob: None,
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
            blob_ttl: Some(7200),
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
            blob_ttl: Some(60),
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
            node_proof: None,
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
            node_proof: None,
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
    // PUBLISH lifetime (09-security-model.md §9.10.12)
    // -----------------------------------------------------------------------

    /// A PUBLISH map with the given lifetime keys, as a peer would send it.
    fn raw_publish(retain: Option<rmpv::Value>, blob_ttl: Option<u32>) -> Vec<u8> {
        let mut map = std::collections::BTreeMap::new();
        map.insert("op".to_string(), rmpv::Value::String("PUBLISH".into()));
        map.insert("ref".to_string(), rmpv::Value::String("life-1".into()));
        map.insert("routing_id".to_string(), rmpv::Value::Binary(vec![7; 32]));
        map.insert("blob".to_string(), rmpv::Value::Binary(vec![1, 2, 3]));
        if let Some(retain) = retain {
            map.insert("retain".to_string(), retain);
        }
        if let Some(ttl) = blob_ttl {
            map.insert("blob_ttl".to_string(), rmpv::Value::Integer(ttl.into()));
        }
        rmp_serde::to_vec_named(&map).unwrap()
    }

    /// The keys an encoded message carries.
    fn keys(bytes: &[u8]) -> Vec<String> {
        let value: rmpv::Value = rmp_serde::from_slice(bytes).unwrap();
        let mut keys: Vec<String> = value
            .as_map()
            .unwrap()
            .iter()
            .map(|(key, _)| key.as_str().unwrap().to_owned())
            .collect();
        keys.sort();
        keys
    }

    fn publish(lifetime: BlobLifetime) -> ClientMessage {
        ClientMessage::Publish {
            ref_id: None,
            routing_id: [7; 32],
            recipient_hint: None,
            lifetime,
            blob: vec![1, 2, 3],
        }
    }

    #[test]
    fn each_lifetime_encodes_as_its_one_section_9_10_12_key() {
        let retained = publish(BlobLifetime::Retained).to_bytes().unwrap();
        let keys_retained = keys(&retained);
        assert!(keys_retained.contains(&"retain".to_string()));
        assert!(!keys_retained.contains(&"blob_ttl".to_string()));
        assert_eq!(
            ClientMessage::from_bytes(&retained).unwrap(),
            publish(BlobLifetime::Retained)
        );

        let ttl = publish(BlobLifetime::Ttl(PublishTtl::of::<60>()))
            .to_bytes()
            .unwrap();
        let keys_ttl = keys(&ttl);
        assert!(keys_ttl.contains(&"blob_ttl".to_string()));
        assert!(!keys_ttl.contains(&"retain".to_string()));
        assert_eq!(
            ClientMessage::from_bytes(&ttl).unwrap(),
            publish(BlobLifetime::Ttl(PublishTtl::of::<60>()))
        );
    }

    #[test]
    fn decoding_refuses_every_lifetime_combination_section_9_10_12_forbids() {
        let cases = [
            (
                raw_publish(Some(rmpv::Value::Boolean(true)), Some(60)),
                LifetimeError::Both,
                code::INVALID_FIELD,
            ),
            (
                raw_publish(None, None),
                LifetimeError::Neither,
                code::MISSING_FIELD,
            ),
            (
                raw_publish(Some(rmpv::Value::Boolean(false)), None),
                LifetimeError::RetainFalse,
                code::INVALID_FIELD,
            ),
            (
                raw_publish(Some(rmpv::Value::Boolean(false)), Some(60)),
                LifetimeError::RetainFalse,
                code::INVALID_FIELD,
            ),
            (
                raw_publish(None, Some(MAX_BLOB_TTL + 1)),
                LifetimeError::TtlOutOfRange(MAX_BLOB_TTL + 1),
                code::TTL_TOO_LONG,
            ),
            (
                raw_publish(None, Some(0)),
                LifetimeError::TtlOutOfRange(0),
                code::TTL_TOO_LONG,
            ),
        ];
        for (bytes, expected, expected_code) in cases {
            let err = ClientMessage::from_bytes(&bytes).unwrap_err();
            let RelayProtocolError::Lifetime { ref_id, error } = &err else {
                panic!("expected a lifetime refusal, got {err:?}");
            };
            assert_eq!(*error, expected);
            assert_eq!(ref_id.as_deref(), Some("life-1"));
            assert_eq!(err.code(), expected_code);
        }
    }

    #[test]
    fn decoding_accepts_each_lifetime_section_9_10_12_allows() {
        let retained = raw_publish(Some(rmpv::Value::Boolean(true)), None);
        assert!(matches!(
            ClientMessage::from_bytes(&retained).unwrap(),
            ClientMessage::Publish {
                lifetime: BlobLifetime::Retained,
                ..
            }
        ));
        for ttl in [MIN_BLOB_TTL, MAX_BLOB_TTL] {
            assert!(matches!(
                ClientMessage::from_bytes(&raw_publish(None, Some(ttl))).unwrap(),
                ClientMessage::Publish {
                    lifetime: BlobLifetime::Ttl(t),
                    ..
                } if t.secs() == ttl
            ));
        }
    }

    #[test]
    fn a_malformed_frame_of_any_other_cause_stays_invalid_message() {
        let mut map = std::collections::BTreeMap::new();
        map.insert("op".to_string(), rmpv::Value::String("PUBLISH".into()));
        map.insert("blob_ttl".to_string(), rmpv::Value::Integer(60.into()));
        let bytes = rmp_serde::to_vec_named(&map).unwrap();
        let err = ClientMessage::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, RelayProtocolError::DeserializationFailed(_)));
        assert_eq!(err.code(), code::INVALID_MESSAGE);
        assert_eq!(err.ref_id(), None);
    }

    #[test]
    fn an_over_long_ref_is_not_echoed_on_a_lifetime_refusal() {
        let mut map = std::collections::BTreeMap::new();
        map.insert("op".to_string(), rmpv::Value::String("PUBLISH".into()));
        map.insert(
            "ref".to_string(),
            rmpv::Value::String("r".repeat(MAX_REF_ID_LEN + 1).into()),
        );
        map.insert("routing_id".to_string(), rmpv::Value::Binary(vec![7; 32]));
        map.insert("blob".to_string(), rmpv::Value::Binary(vec![1]));
        let bytes = rmp_serde::to_vec_named(&map).unwrap();
        let err = ClientMessage::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            RelayProtocolError::Lifetime {
                ref_id: None,
                error: LifetimeError::Neither
            }
        ));
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
            lifetime: BlobLifetime::Ttl(PublishTtl::of::<3600>()),
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
            lifetime: BlobLifetime::Ttl(PublishTtl::of::<60>()),
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
            lifetime: BlobLifetime::Ttl(PublishTtl::of::<60>()),
            blob: vec![],
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("blob must be"));
    }

    /// The one fallible constructor refuses each value just outside the
    /// §9.10.12 range with `4011`, accepts both bounds, and is the path
    /// `TryFrom` and decoding take.
    #[test]
    fn publish_ttl_refuses_each_side_of_the_range_and_accepts_both_bounds() {
        for secs in [0, MAX_BLOB_TTL + 1] {
            let err = PublishTtl::new(secs).unwrap_err();
            assert_eq!(err, LifetimeError::TtlOutOfRange(secs));
            assert_eq!(err.code(), code::TTL_TOO_LONG);
            assert_eq!(PublishTtl::try_from(secs), Err(err));
            let wire = rmp_serde::to_vec(&secs).unwrap();
            assert!(
                rmp_serde::from_slice::<PublishTtl>(&wire).is_err(),
                "{secs}"
            );
        }
        for secs in [MIN_BLOB_TTL, MAX_BLOB_TTL] {
            assert_eq!(PublishTtl::new(secs).map(PublishTtl::secs), Ok(secs));
            let wire = rmp_serde::to_vec(&secs).unwrap();
            assert_eq!(
                rmp_serde::from_slice::<PublishTtl>(&wire).unwrap().secs(),
                secs
            );
        }
        assert_eq!(PublishTtl::MIN.secs(), MIN_BLOB_TTL);
        assert_eq!(PublishTtl::MAX.secs(), MAX_BLOB_TTL);
    }

    #[test]
    fn validate_publish_ttl_boundary_values() {
        // Minimum valid TTL
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: [0x00; 32],
            recipient_hint: None,
            lifetime: BlobLifetime::Ttl(PublishTtl::MIN),
            blob: vec![0x01],
        };
        assert!(msg.validate().is_ok());

        // Maximum valid TTL
        let msg = ClientMessage::Publish {
            ref_id: None,
            routing_id: [0x00; 32],
            recipient_hint: None,
            lifetime: BlobLifetime::Ttl(PublishTtl::MAX),
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
            lifetime: BlobLifetime::Ttl(PublishTtl::of::<60>()),
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
            lifetime: BlobLifetime::Ttl(PublishTtl::of::<60>()),
            blob: vec![0x01],
        };
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn validate_query_limit_too_high() {
        let msg = ClientMessage::Query {
            proof_nonce: None,
            ref_id: None,
            routing_id: [0x00; 32],
            since: None,
            after_blob: None,
            limit: Some(MAX_QUERY_LIMIT + 1),
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("limit"));
    }

    #[test]
    fn validate_query_limit_zero() {
        let msg = ClientMessage::Query {
            proof_nonce: None,
            ref_id: None,
            routing_id: [0x00; 32],
            since: None,
            after_blob: None,
            limit: Some(0),
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("limit"));
    }

    #[test]
    fn validate_query_limit_at_max() {
        let msg = ClientMessage::Query {
            proof_nonce: None,
            ref_id: None,
            routing_id: [0x00; 32],
            since: None,
            after_blob: None,
            limit: Some(MAX_QUERY_LIMIT),
        };
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn validate_query_limit_none_is_valid() {
        let msg = ClientMessage::Query {
            proof_nonce: None,
            ref_id: None,
            routing_id: [0x00; 32],
            since: None,
            after_blob: None,
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
                    lifetime: BlobLifetime::Ttl(PublishTtl::of::<1>()),
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
                    proof_nonce: None,
                    ref_id: None,
                    routing_id: [0; 32],
                    since: None,
                    after_blob: None,
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
                    blob_ttl: Some(1),
                    stored_at: 0,
                    blob: vec![0x01],
                },
                "BLOB",
            ),
            (
                RelayMessage::Event {
                    node_proof: None,
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
            lifetime: BlobLifetime::Ttl(PublishTtl::of::<60>()),
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

    #[test]
    fn client_message_from_bytes_rejects_oversize() {
        let oversized = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let result = ClientMessage::from_bytes(&oversized);
        assert!(
            matches!(
                result,
                Err(RelayProtocolError::MessageTooLarge { size, max })
                    if size == MAX_MESSAGE_SIZE + 1 && max == MAX_MESSAGE_SIZE
            ),
            "expected MessageTooLarge, got: {result:?}"
        );
    }

    #[test]
    fn relay_message_from_bytes_rejects_oversize() {
        let oversized = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let result = RelayMessage::from_bytes(&oversized);
        assert!(
            matches!(
                result,
                Err(RelayProtocolError::MessageTooLarge { size, max })
                    if size == MAX_MESSAGE_SIZE + 1 && max == MAX_MESSAGE_SIZE
            ),
            "expected MessageTooLarge, got: {result:?}"
        );
    }

    #[test]
    fn client_message_from_bytes_accepts_at_max_size() {
        // A buffer exactly at the limit is accepted (rejected only if strictly greater).
        // The payload is not valid MessagePack so we get DeserializationFailed, not
        // MessageTooLarge -- this confirms the size gate did NOT trigger.
        let at_limit = vec![0xFFu8; MAX_MESSAGE_SIZE];
        let result = ClientMessage::from_bytes(&at_limit);
        assert!(
            matches!(result, Err(RelayProtocolError::DeserializationFailed(_))),
            "expected DeserializationFailed at limit (not MessageTooLarge), got: {result:?}"
        );
    }

    #[test]
    fn relay_message_from_bytes_accepts_at_max_size() {
        let at_limit = vec![0xFFu8; MAX_MESSAGE_SIZE];
        let result = RelayMessage::from_bytes(&at_limit);
        assert!(
            matches!(result, Err(RelayProtocolError::DeserializationFailed(_))),
            "expected DeserializationFailed at limit (not MessageTooLarge), got: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Wire format field name compliance (ADR-004)
    // -----------------------------------------------------------------------

    #[test]
    fn client_publish_wire_field_ref_not_ref_id() {
        // ADR-004 specifies the wire field name is "ref", not "ref_id".
        let msg = ClientMessage::Publish {
            ref_id: Some("test-ref".to_string()),
            routing_id: [0xAA; 32],
            recipient_hint: None,
            lifetime: BlobLifetime::Ttl(PublishTtl::of::<60>()),
            blob: vec![0x01],
        };
        let bytes = msg.to_bytes().unwrap();
        let map: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).unwrap();

        assert!(
            map.contains_key("ref"),
            "wire format must use 'ref', not 'ref_id'"
        );
        assert!(
            !map.contains_key("ref_id"),
            "wire format must not contain 'ref_id'"
        );
        assert_eq!(map["ref"].as_str(), Some("test-ref"));
    }

    #[test]
    fn relay_event_wire_field_type_not_event_type() {
        // ADR-004 specifies the wire field name is "type", not "event_type".
        let msg = RelayMessage::Event {
            node_proof: None,
            ref_id: Some("evt-1".to_string()),
            event_type: "backfill_complete".to_string(),
        };
        let bytes = msg.to_bytes().unwrap();
        let map: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).unwrap();

        assert!(
            map.contains_key("type"),
            "wire format must use 'type', not 'event_type'"
        );
        assert!(
            !map.contains_key("event_type"),
            "wire format must not contain 'event_type'"
        );
        assert_eq!(map["type"].as_str(), Some("backfill_complete"));

        // Also verify ref field name.
        assert!(
            map.contains_key("ref"),
            "wire format must use 'ref', not 'ref_id'"
        );
        assert!(
            !map.contains_key("ref_id"),
            "wire format must not contain 'ref_id'"
        );
    }

    #[test]
    fn relay_ok_wire_field_ref_not_ref_id() {
        let msg = RelayMessage::Ok {
            ref_id: Some("ok-ref".to_string()),
            blob_id: None,
        };
        let bytes = msg.to_bytes().unwrap();
        let map: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).unwrap();

        assert!(
            map.contains_key("ref"),
            "wire format must use 'ref', not 'ref_id'"
        );
        assert!(
            !map.contains_key("ref_id"),
            "wire format must not contain 'ref_id'"
        );
    }

    #[test]
    fn relay_err_wire_field_ref_not_ref_id() {
        let msg = RelayMessage::Err {
            ref_id: Some("err-ref".to_string()),
            code: 4000,
            msg: "test".to_string(),
        };
        let bytes = msg.to_bytes().unwrap();
        let map: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).unwrap();

        assert!(
            map.contains_key("ref"),
            "wire format must use 'ref', not 'ref_id'"
        );
        assert!(
            !map.contains_key("ref_id"),
            "wire format must not contain 'ref_id'"
        );
    }

    #[test]
    fn all_client_variants_use_ref_wire_name() {
        // Verify every ClientMessage variant with a ref_id field
        // serializes it as "ref" on the wire.
        let variants: Vec<ClientMessage> = vec![
            ClientMessage::Publish {
                ref_id: Some("r".into()),
                routing_id: [0; 32],
                recipient_hint: None,
                lifetime: BlobLifetime::Ttl(PublishTtl::of::<1>()),
                blob: vec![0x01],
            },
            ClientMessage::Subscribe {
                ref_id: Some("r".into()),
                routing_id: [0; 32],
                since: None,
            },
            ClientMessage::Unsubscribe {
                ref_id: Some("r".into()),
                routing_id: [0; 32],
            },
            ClientMessage::Query {
                proof_nonce: None,
                ref_id: Some("r".into()),
                routing_id: [0; 32],
                since: None,
                after_blob: None,
                limit: None,
            },
            ClientMessage::Delete {
                ref_id: Some("r".into()),
                blob_id: [0; 32],
            },
            ClientMessage::BridgeRegister {
                ref_id: Some("r".into()),
                routing_id: [0; 32],
                public_key: [0; 32],
                signature: [0; 64],
                timestamp: 0,
                target_relay_hint: None,
            },
            ClientMessage::BridgeData {
                ref_id: Some("r".into()),
                target_routing_id: [0; 32],
                payload: vec![0x01],
            },
        ];

        for msg in variants {
            let bytes = msg.to_bytes().unwrap();
            let map: std::collections::BTreeMap<String, rmpv::Value> =
                rmp_serde::from_slice(&bytes).unwrap();
            assert!(
                map.contains_key("ref"),
                "{msg:?}: wire format must use 'ref'"
            );
            assert!(
                !map.contains_key("ref_id"),
                "{msg:?}: wire format must not contain 'ref_id'"
            );
        }
    }

    #[test]
    fn wire_format_deserializes_from_spec_field_names() {
        // Verify that messages using spec-compliant field names ("ref", "type")
        // deserialize correctly — simulates receiving from a conformant peer.
        let mut map = std::collections::BTreeMap::new();
        map.insert("op".to_string(), rmpv::Value::String("EVENT".into()));
        map.insert("ref".to_string(), rmpv::Value::String("evt-deser".into()));
        map.insert(
            "type".to_string(),
            rmpv::Value::String("query_complete".into()),
        );

        let bytes = rmp_serde::to_vec_named(&map).unwrap();
        let msg = RelayMessage::from_bytes(&bytes).unwrap();

        assert_eq!(
            msg,
            RelayMessage::Event {
                node_proof: None,
                ref_id: Some("evt-deser".to_string()),
                event_type: "query_complete".to_string(),
            }
        );
    }

    /// The value an encoded message carries under `key`, if any.
    fn field(bytes: &[u8], key: &str) -> Option<rmpv::Value> {
        let value: rmpv::Value = rmp_serde::from_slice(bytes).unwrap();
        value
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v.clone())
    }

    /// ADR-004's QUERY row: `proof_nonce: bin32?`. Present, it rides as a
    /// 32-byte `bin` under the key `proof_nonce` and round-trips; absent,
    /// the key is omitted; a `bin` of any other width is refused.
    #[test]
    fn query_proof_nonce_is_an_optional_bin32_per_adr_004() {
        let query = |proof_nonce| ClientMessage::Query {
            ref_id: Some("q-nonce".to_string()),
            routing_id: [0x11; 32],
            since: Some(5),
            after_blob: Some([0x22; 32]),
            limit: Some(16),
            proof_nonce,
        };
        let with = query(Some([0x5a; 32]));
        let bytes = with.to_bytes().unwrap();
        assert_eq!(
            field(&bytes, "proof_nonce"),
            Some(rmpv::Value::Binary(vec![0x5a; 32]))
        );
        assert_eq!(ClientMessage::from_bytes(&bytes).unwrap(), with);

        let without = query(None).to_bytes().unwrap();
        assert_eq!(field(&without, "proof_nonce"), None);
        assert_eq!(ClientMessage::from_bytes(&without).unwrap(), query(None));

        let mut map = std::collections::BTreeMap::new();
        map.insert("op".to_string(), rmpv::Value::String("QUERY".into()));
        map.insert(
            "routing_id".to_string(),
            rmpv::Value::Binary(vec![0x11; 32]),
        );
        map.insert(
            "proof_nonce".to_string(),
            rmpv::Value::Binary(vec![0x5a; 31]),
        );
        let short = rmp_serde::to_vec_named(&map).unwrap();
        assert!(ClientMessage::from_bytes(&short).is_err());
    }

    /// ADR-004's EVENT row: `query_complete` carries `node_proof: bin200?`.
    /// Present, it rides as a 200-byte `bin` under the key `node_proof` and
    /// round-trips; absent, the key is omitted; a `bin` of any other width
    /// is refused.
    #[test]
    fn query_complete_node_proof_is_an_optional_bin200_per_adr_004() {
        assert_eq!(NODE_PROOF_LEN, 200);
        let event = |node_proof| RelayMessage::Event {
            ref_id: Some("q-nonce".to_string()),
            event_type: "query_complete".to_string(),
            node_proof,
        };
        let proof: Vec<u8> = (0..=199).collect();
        let with = event(Some(Box::new(
            <[u8; NODE_PROOF_LEN]>::try_from(proof.as_slice()).unwrap(),
        )));
        let bytes = with.to_bytes().unwrap();
        assert_eq!(
            field(&bytes, "node_proof"),
            Some(rmpv::Value::Binary(proof.clone()))
        );
        assert_eq!(RelayMessage::from_bytes(&bytes).unwrap(), with);

        let without = event(None).to_bytes().unwrap();
        assert_eq!(field(&without, "node_proof"), None);
        assert_eq!(RelayMessage::from_bytes(&without).unwrap(), event(None));

        let mut map = std::collections::BTreeMap::new();
        map.insert("op".to_string(), rmpv::Value::String("EVENT".into()));
        map.insert(
            "type".to_string(),
            rmpv::Value::String("query_complete".into()),
        );
        map.insert(
            "node_proof".to_string(),
            rmpv::Value::Binary(proof[..199].to_vec()),
        );
        let short = rmp_serde::to_vec_named(&map).unwrap();
        assert!(RelayMessage::from_bytes(&short).is_err());
    }
}
