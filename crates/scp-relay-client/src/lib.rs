//! SCP relay wire protocol — the `ClientMessage` / `RelayMessage` types and
//! their `MessagePack` wire format, shared by the native relay and the
//! in-browser client.
//!
//! This crate is the single home for the relay wire types (ADR-057 Slice 3,
//! Decision D5). It is a wasm-safe leaf: it depends only on `scp-protocol`
//! (for the `serde_util::serde_bounded_bytes` helper) plus `serde` /
//! `serde_bytes` / `rmp-serde` / `thiserror`, so it compiles to
//! `wasm32-unknown-unknown` and the native relay and the future in-browser
//! transport share ONE definition — no forked copy, no byte-parity tax.
//!
//! See ADR-004 in `.docs/adrs/phase-1.md` for the full wire format
//! specification, and ADR-057 for the shared-crate rationale.

mod error;
mod protocol;

pub use error::{RelayProtocolError, code};
pub use protocol::{
    ClientMessage, DEFAULT_QUERY_LIMIT, MAX_BLOB_SIZE, MAX_BLOB_TTL, MAX_MESSAGE_SIZE,
    MAX_QUERY_LIMIT, MAX_REF_ID_LEN, MIN_BLOB_TTL, RelayMessage,
};
