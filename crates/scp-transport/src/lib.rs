//! Transport abstraction layer for SCP (Shared Context Protocol).
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

pub mod backoff;
#[cfg(feature = "coap")]
pub mod coap;
pub mod config;
pub mod cover_traffic;
pub mod error;
pub mod heartbeat;
#[cfg(feature = "http3")]
pub mod http3;
pub mod manager;
pub mod nat;
pub mod native;
pub mod pool;
pub mod profile;
pub mod provider;
#[cfg(feature = "quic")]
pub mod quic;
pub mod relay;
pub mod scoring;
pub mod traits;
#[cfg(feature = "udp")]
pub mod udp;
#[cfg(any(feature = "http3", feature = "webtransport-wasm"))]
pub mod webtransport;

// Re-export primary types at the crate level for convenience.
pub use backoff::ReconnectBackoff;
pub use config::{DefaultRelayResolver, ResolveRelays, TransportConfig};
pub use cover_traffic::{
    CoverAction, CoverTrafficConfig, CoverTrafficGenerator, CoverTrafficSender, pad_to_bucket,
};
pub use error::TransportError;
pub use heartbeat::{
    HeartbeatConfig, HeartbeatConfigError, HeartbeatMonitor, SuppressionSuspected,
};
pub use manager::{EvictionOutcome, TransportManager};
pub use nat::{
    MappingProtocol, NatKeepalive, NatProbeResult, NatProber, NatTierChange, NatType, PortMapper,
    PortMappingError, PortMappingManager, PortMappingResult, StunEndpoint,
};
pub use pool::{ConnectionPool, PoolKey, TransportType};
pub use profile::{CoverTrafficTier, TransportProfile};
pub use provider::RelayTransportProvider;
pub use scoring::SuppressionWarning;
pub use traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter, TransportEvent};
