//! WebTransport server-side listener for SCP relay.
//!
//! Accepts QUIC connections, establishes HTTP/3 sessions, and dispatches
//! bidirectional streams to [`WebTransportSessionHandler`] instances. Uses
//! raw h3 bidirectional streams (same framing as the QUIC listener) rather
//! than the WebTransport-specific CONNECT protocol, since h3-webtransport
//! has dependency compatibility issues with h3 0.0.8.
//!
//! Each bidirectional stream carries a single SCP operation using
//! length-prefixed `MessagePack` framing (4-byte big-endian length + payload),
//! identical to the QUIC listener (spec §10.14.1).
//!
//! # Architecture
//!
//! The listener shares the relay's subscription registry, blob storage,
//! and publish rate limiter with WebSocket and QUIC handlers (ADR-037 AC3,
//! spec §10.14.3). A subscription created via WebTransport is visible to
//! QUIC and WebSocket subscribers and vice versa.
//!
//! See spec section 10.15.2 "WebTransport Server Sessions" and SCP-259.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::native::did_slot::DidSlotRegistry;
use crate::native::storage::BlobStorage;
use crate::relay::rate_limit::{ConnectionTracker, PublishRateLimiter};
use crate::relay::subscription::{self, SubscriptionRegistry};

use super::session::{SessionId, WebTransportSessionConfig, WebTransportSessionHandler};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the WebTransport listener.
///
/// Controls connection limits and inherits relay-level settings for blob
/// handling and rate limiting.
#[derive(Debug, Clone)]
pub struct WebTransportListenerConfig {
    /// Address to bind the QUIC listener to (UDP).
    pub bind_addr: SocketAddr,
    /// Maximum concurrent connections from a single IP address (default: 10).
    pub max_connections_per_ip: usize,
    /// Maximum total concurrent connections across all IPs (default: 1000).
    pub max_total_connections: usize,
    /// Session-level configuration for WebTransport sessions.
    pub session_config: WebTransportSessionConfig,
}

impl Default for WebTransportListenerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 9444)),
            max_connections_per_ip: 10,
            max_total_connections: 1000,
            session_config: WebTransportSessionConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during WebTransport listener operation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum WebTransportListenerError {
    /// The listener could not bind to the configured address.
    #[error("bind failed: {0}")]
    BindFailed(String),

    /// TLS configuration error.
    #[error("TLS configuration error: {0}")]
    TlsError(String),

    /// The listener could not accept a connection.
    #[error("accept failed: {0}")]
    AcceptFailed(String),
}

// ---------------------------------------------------------------------------
// Shutdown handle
// ---------------------------------------------------------------------------

/// Handle for gracefully shutting down a running WebTransport listener.
///
/// Dropping the handle does **not** shut down the listener. Call
/// [`shutdown`](Self::shutdown) explicitly.
#[derive(Debug, Clone)]
pub struct WebTransportShutdownHandle {
    token: CancellationToken,
}

impl WebTransportShutdownHandle {
    /// Signals the WebTransport listener to stop accepting new connections.
    pub fn shutdown(&self) {
        self.token.cancel();
    }

    /// Returns `true` if shutdown has been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.token.is_cancelled()
    }
}

// ---------------------------------------------------------------------------
// WebTransportListener
// ---------------------------------------------------------------------------

/// Relay-side WebTransport listener that accepts QUIC/HTTP/3 connections.
///
/// Each incoming connection is upgraded to an HTTP/3 session, and
/// bidirectional streams are dispatched as individual SCP operations.
/// The subscription registry and blob storage are shared with the
/// WebSocket and QUIC servers.
///
/// # Type parameter
///
/// `S` is the blob storage backend, shared with other relay transports.
pub struct WebTransportListener<S: BlobStorage> {
    config: WebTransportListenerConfig,
    storage: Arc<S>,
    subscriptions: SubscriptionRegistry,
    connection_tracker: ConnectionTracker,
    publish_rate_limiter: PublishRateLimiter,
    did_slots: DidSlotRegistry,
}

impl<S: BlobStorage + 'static> WebTransportListener<S> {
    /// Creates a new WebTransport listener with the given configuration
    /// and shared state.
    ///
    /// The `storage`, `subscriptions`, `publish_rate_limiter`,
    /// `connection_tracker`, and `did_slots` are shared with the WebSocket relay
    /// server, QUIC listener, and UDP/DTLS listener, enabling cross-transport
    /// message delivery, unified rate limiting, and one shared DID-record slot
    /// index so slot-exclusivity holds across every transport on the shared blob
    /// store (ADR-037 AC3, §3.10.2). Obtain the shared registry via
    /// [`RelayServer::did_slot_registry`](crate::native::server::RelayServer::did_slot_registry)
    /// and set `config.session_config.did_record_validation` to the relay's mode.
    #[must_use]
    pub const fn new(
        config: WebTransportListenerConfig,
        storage: Arc<S>,
        subscriptions: SubscriptionRegistry,
        publish_rate_limiter: PublishRateLimiter,
        connection_tracker: ConnectionTracker,
        did_slots: DidSlotRegistry,
    ) -> Self {
        Self {
            config,
            storage,
            subscriptions,
            connection_tracker,
            publish_rate_limiter,
            did_slots,
        }
    }

    /// Returns the next globally unique session ID.
    ///
    /// Uses the shared global counter from [`subscription::next_owner_id()`]
    /// to prevent cross-transport `owner_id` collisions in the shared
    /// subscription registry.
    #[allow(clippy::unused_self)] // Instance method for API consistency.
    fn next_session_id(&self) -> SessionId {
        SessionId(subscription::next_owner_id())
    }

    /// Creates a [`WebTransportSessionHandler`] for a new session.
    ///
    /// This is the primary integration point: the HTTP/3 listener (in
    /// `http3/adapter.rs`) calls this to create a session handler for
    /// each accepted connection. The handler provides full operation
    /// dispatch via [`dispatch_message`](WebTransportSessionHandler::dispatch_message)
    /// and [`dispatch_message_multi`](WebTransportSessionHandler::dispatch_message_multi).
    #[must_use]
    pub fn create_session(
        &self,
        remote_ip: std::net::IpAddr,
        shutdown_token: CancellationToken,
    ) -> WebTransportSessionHandler<S> {
        let session_id = self.next_session_id();
        WebTransportSessionHandler::new(
            session_id,
            self.config.session_config.clone(),
            Arc::clone(&self.storage),
            Arc::clone(&self.subscriptions),
            shutdown_token,
            self.publish_rate_limiter.clone(),
            remote_ip,
            self.did_slots.clone(),
        )
    }

    /// Returns a reference to the connection tracker.
    #[must_use]
    pub const fn connection_tracker(&self) -> &ConnectionTracker {
        &self.connection_tracker
    }

    /// Returns a reference to the listener configuration.
    #[must_use]
    pub const fn config(&self) -> &WebTransportListenerConfig {
        &self.config
    }

    /// Spawns the background rate-limiter cleanup task.
    ///
    /// Must be called once when the WebTransport listener starts accepting
    /// connections. The task evicts stale per-IP publish rate-limiter
    /// buckets to prevent unbounded memory growth, matching the cleanup
    /// pattern used by the QUIC listener and WebSocket server.
    pub fn spawn_cleanup(&self, shutdown_token: CancellationToken) {
        let rate_limiter = self.publish_rate_limiter.clone();
        tokio::spawn(async move {
            rate_limiter
                .cleanup_loop(
                    Duration::from_mins(1),
                    Duration::from_secs(90),
                    shutdown_token,
                )
                .await;
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::native::storage::InMemoryBlobStorage;
    use crate::relay::rate_limit::PublishRateLimiter;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_listener() -> WebTransportListener<InMemoryBlobStorage> {
        let storage = Arc::new(InMemoryBlobStorage::new());
        let subscriptions = crate::relay::subscription::new_registry();
        let rate_limiter = PublishRateLimiter::new(100);
        let conn_tracker = crate::relay::rate_limit::new_connection_tracker();

        WebTransportListener::new(
            WebTransportListenerConfig::default(),
            storage,
            subscriptions,
            rate_limiter,
            conn_tracker,
            DidSlotRegistry::new(),
        )
    }

    #[test]
    fn listener_creates_sessions_with_unique_ids() {
        let listener = make_listener();
        let token = CancellationToken::new();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        let s1 = listener.create_session(ip, token.clone());
        let s2 = listener.create_session(ip, token.clone());
        let s3 = listener.create_session(ip, token);

        // IDs must be unique and monotonically increasing (global counter).
        assert_ne!(s1.session_id(), s2.session_id());
        assert_ne!(s2.session_id(), s3.session_id());
        assert!(s1.session_id().0 < s2.session_id().0);
        assert!(s2.session_id().0 < s3.session_id().0);
    }

    #[test]
    fn listener_config_defaults() {
        let config = WebTransportListenerConfig::default();
        assert_eq!(config.bind_addr, SocketAddr::from(([127, 0, 0, 1], 9444)));
        assert_eq!(config.max_connections_per_ip, 10);
        assert_eq!(config.max_total_connections, 1000);
    }

    #[test]
    fn shutdown_handle_tracks_state() {
        let token = CancellationToken::new();
        let handle = WebTransportShutdownHandle { token };

        assert!(!handle.is_shutdown());
        handle.shutdown();
        assert!(handle.is_shutdown());
    }
}
