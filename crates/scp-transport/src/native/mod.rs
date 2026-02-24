//! SCP native relay protocol types and wire format.
//!
//! This module defines the message types for the SCP native relay -- a
//! purpose-built, WebSocket-based store-and-forward relay for SCP envelopes.
//! The relay is deliberately simple: accept opaque blobs, hold them for a TTL,
//! deliver to subscribers, delete on expiry or request.
//!
//! # Wire format
//!
//! All messages are serialized as `MessagePack` maps over WebSocket binary
//! frames. Each message has a required `op` field (string) identifying the
//! operation, plus operation-specific fields. Unknown fields MUST be ignored
//! for forward compatibility.
//!
//! Binary fields (`routing_id`, `blob_id`, `recipient_hint`, `blob`) use
//! `MessagePack`'s native `bin` type -- no Base64 or hex encoding.
//!
//! # Connection
//!
//! Connection URL: `wss://<host>/scp/v1`. TLS 1.3 required. The URL path
//! encodes the protocol version -- no in-band version negotiation.
//!
//! # Keepalive
//!
//! Client MUST send `PING` every 30 seconds. Relay MAY close idle connections
//! after 90 seconds of no messages. WebSocket-level pings (opcode 0x9) are
//! independent TCP-level liveness checks.
//!
//! See ADR-004 in `.docs/adrs/phase-1.md` for the full specification.

pub mod error;
pub mod protocol;

// Re-export primary types for convenience.
pub use error::{NativeProtocolError, code};
pub use protocol::{
    ClientMessage, DEFAULT_QUERY_LIMIT, MAX_BLOB_SIZE, MAX_BLOB_TTL, MAX_QUERY_LIMIT,
    MAX_REF_ID_LEN, MIN_BLOB_TTL, RelayMessage,
};
