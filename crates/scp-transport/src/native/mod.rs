//! SCP native relay -- server, adapters, and blob storage.
//!
//! This module implements the SCP native relay -- a purpose-built,
//! WebSocket-based store-and-forward relay for SCP envelopes. The relay is
//! deliberately simple: accept opaque blobs, hold them for a TTL, deliver to
//! subscribers, delete on expiry or request. The wire types it speaks
//! ([`scp_relay_client::ClientMessage`] / [`scp_relay_client::RelayMessage`])
//! live in the wasm-safe `scp-relay-client` leaf, shared with the in-browser
//! client (ADR-057 Slice 3, Decision D5).
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

pub mod adapter;
pub mod cert_pin;
pub(crate) mod client;
#[cfg(feature = "combined")]
pub mod combined;
pub mod did_slot;
#[cfg(feature = "local-cache")]
pub mod local_cache;
#[cfg(feature = "postgres-blob")]
pub mod postgres_blob;
#[cfg(feature = "redb-blob")]
pub mod redb_blob;
pub mod relay_persistence;
pub mod relay_publisher;
pub mod relay_querier;
#[cfg(feature = "s3-blob")]
pub mod s3_blob;
pub mod server;
#[cfg(feature = "sqlite-blob")]
pub mod sqlite_blob;
pub mod storage;

// Re-export primary types for convenience.
//
// The relay wire types (`ClientMessage`, `RelayMessage`, the constants, and
// `RelayProtocolError` / `code`) now live in the wasm-safe `scp-relay-client`
// leaf so the native relay and the in-browser client share ONE definition
// (ADR-057 Slice 3, Decision D5). Import them directly from `scp_relay_client`;
// they are deliberately NOT re-exported here (a shim re-export is forbidden by
// the ADR-057 Amendment — see `scripts/check-no-shim-reexports.sh`).
pub use adapter::NativeRelayAdapter;
pub use cert_pin::{CertPinResult, CertificatePin};
pub use relay_publisher::TransportRelayPublisher;
pub use relay_querier::TransportRelayQuerier;
