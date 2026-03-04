//! UDP/DTLS transport for constrained devices.
//!
//! This module implements the SCP-native constrained device transport per
//! spec section 10.16.1 (`MessagePack`-over-DTLS). It uses the same `MessagePack`
//! wire format as ADR-004 over DTLS 1.3 datagrams instead of WebSocket frames.
//!
//! # Design
//!
//! - **DTLS 1.3 session.** Client establishes a DTLS 1.3 session with the
//!   relay for transport encryption.
//! - **Datagram semantics.** Each operation (PUBLISH, QUERY, DELETE) is an
//!   independent DTLS datagram (or datagram sequence for payloads exceeding
//!   the path MTU).
//! - **Session resumption.** DTLS session tickets enable 0-RTT reconnection,
//!   avoiding a full handshake on subsequent operations.
//! - **No SUBSCRIBE.** `subscribe()` returns [`TransportError::NotSupported`]
//!   -- constrained devices poll via `query()` at configurable intervals.
//!
//! # Modules
//!
//! - [`adapter`] -- client-side [`UdpDtlsAdapter`] implementing
//!   [`TransportAdapter`](crate::TransportAdapter).
//! - [`listener`] -- relay-side [`UdpDtlsListener`] accepting DTLS datagrams
//!   and dispatching to shared blob storage.
//!
//! # Trade-offs (section 10.16.3)
//!
//! Constrained devices sacrifice cover traffic, suppression resistance, and
//! real-time delivery for minimal connection overhead. They typically operate
//! behind a gateway agent that bridges to the full SCP relay network.
//!
//! See ADR-037 in `.docs/adrs/phase-2.md` for the transport binding design.
//!
//! [`TransportError::NotSupported`]: crate::error::TransportError::NotSupported

pub mod adapter;
pub mod dtls;
pub mod listener;

pub use adapter::UdpDtlsAdapter;
pub use listener::{UdpDtlsListener, UdpDtlsListenerConfig};
