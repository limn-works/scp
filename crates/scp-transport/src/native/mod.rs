//! SCP native relay: WebSocket store-and-forward. See ADR-004.
//!
//! This module implements the wire format for the SCP native relay protocol:
//! message types, `MessagePack` serialization, error codes, and validation.
//!
//! # Modules
//!
//! - [`error`] — Error codes (4xxx client, 5xxx server) and protocol error
//!   types.
//! - [`protocol`] — [`ClientMessage`](protocol::ClientMessage) and
//!   [`RelayMessage`](protocol::RelayMessage) enums with `MessagePack`
//!   serialization.

pub mod error;
pub mod protocol;
