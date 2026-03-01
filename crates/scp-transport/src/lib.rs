//! Transport abstraction layer for SCP (Shareable Context Protocol).
//!
//! `scp-transport` defines the [`TransportAdapter`] trait that all SCP transport
//! adapters implement, along with supporting types ([`BlobId`], [`RoutingId`],
//! [`TransportError`], [`TransportEvent`]) and the [`TransportManager`] struct
//! for multi-adapter routing.
//!
//! The trait is deliberately thin: five async methods covering send, subscribe,
//! unsubscribe, query, and delete. SCP is transport-independent -- no single
//! transport is "primary." The protocol functions correctly on any transport
//! that implements the abstraction.
//!
//! # Architecture
//!
//! - **[`TransportAdapter`]** -- the trait all adapters implement. Phase 1
//!   provides the SCP native relay adapter. Future phases add Nostr, Matrix,
//!   Hyperswarm, libp2p, and others.
//! - **[`TransportManager`]** -- holds one or more adapters and provides a
//!   unified interface. Phase 1 supports a single adapter; multi-adapter
//!   routing is Phase 2+.
//! - **[`TransportError`]** -- transport-level errors.
//! - **[`TransportEvent`]** -- events yielded by subscription streams.
//! - **[`BlobId`]** -- opaque blob identifier (SHA-256 hash of the blob).
//! - **[`RoutingId`]** -- per-context pseudonym used for routing.
//!
//! See ADR-005 in `.docs/adrs/phase-1.md` for the full transport abstraction
//! design.

#![forbid(unsafe_code)]

pub mod config;
pub mod cover_traffic;
pub mod error;
pub mod heartbeat;
pub mod manager;
pub mod native;
pub mod relay;
pub mod scoring;
pub mod traits;

// Re-export primary types at the crate level for convenience.
pub use config::{DefaultRelayResolver, ResolveRelays, TransportConfig};
pub use cover_traffic::{
    CoverAction, CoverTrafficConfig, CoverTrafficGenerator, CoverTrafficSender,
};
pub use error::TransportError;
pub use heartbeat::{HeartbeatConfig, HeartbeatMonitor, SuppressionSuspected};
pub use manager::TransportManager;
pub use scoring::SuppressionWarning;
pub use traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter, TransportEvent};
