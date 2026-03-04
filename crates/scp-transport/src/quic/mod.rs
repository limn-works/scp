//! QUIC transport adapter for SCP (section 10.14).
//!
//! QUIC replaces WebSocket for native (non-browser) clients. Same relay, same
//! `MessagePack` wire format (ADR-004), different framing. QUIC connections use
//! per-operation bidirectional streams rather than multiplexing all operations
//! over a single bidirectional channel.
//!
//! # Benefits over WebSocket
//!
//! - **No head-of-line blocking.** Each operation runs on an independent QUIC
//!   stream -- a slow packet on one stream does not block others.
//! - **Connection migration.** When the client's IP changes (e.g., Wi-Fi to
//!   cellular), QUIC migrates the connection without closing it.
//! - **0-RTT resumption.** Reconnections skip the full handshake using session
//!   tickets, eliminating round-trip latency.
//! - **Native keepalive.** QUIC PING frames (RFC 9000 section 19.2) replace
//!   application-level PING/PONG.
//!
//! # Module structure
//!
//! - [`adapter`] -- [`QuicAdapter`] implementing [`TransportAdapter`](crate::TransportAdapter).
//! - [`lifecycle`] -- Connection lifecycle management (0-RTT, migration,
//!   keepalive, reconnection with exponential backoff).
//! - [`listener`] -- Relay-side QUIC listener (section 10.14.3).
//! - [`streams`] -- Per-operation bidirectional stream management.
//!
//! See section 10.14 in `.docs/specs/10-infrastructure-and-self-hosting.md` and
//! ADR-037 in `.docs/adrs/phase-2.md` for the full specification.

pub mod adapter;
pub mod lifecycle;
pub mod listener;
pub mod streams;

pub use adapter::QuicAdapter;
pub use lifecycle::{
    ConnectionMigrationEvent, QuicKeepaliveConfig, QuicLifecycleManager, ReconnectBackoff,
    SessionTicketStore,
};
pub use listener::{QuicListener, QuicListenerConfig, QuicListenerError};
