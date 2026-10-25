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
use crate::relay::push_gate::LiveRelayUrl;
use crate::relay::rate_limit::{ConnectionTracker, PublishRateLimiter};
use crate::relay::subscription::{self, SubscriptionRegistry};

use super::session::{SessionId, WebTransportSessionConfig, WebTransportSessionHandler};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the WebTransport listener.
///
/// Controls connection limits and inherits relay-level settings for blob
/// handling and rate limiting. Build it with
/// [`WebTransportListenerConfig::defaults`], which takes the relay's URL.
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

impl WebTransportListenerConfig {
    /// The defaults for every field, with `relay_url` as the relay's URL.
    #[must_use]
    pub fn defaults(relay_url: LiveRelayUrl) -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 9444)),
            max_connections_per_ip: 10,
            max_total_connections: 1000,
            session_config: WebTransportSessionConfig::defaults(relay_url),
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
    /// Set `config.session_config.relay_url` to a clone of the relay's handle
    /// and `config.session_config.push` to the relay's value too, so push
    /// messages are intercepted and follow a URL change (§10.7.1).
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
            WebTransportListenerConfig::defaults(crate::relay::push_gate::test_relay_url()),
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
        let config =
            WebTransportListenerConfig::defaults(crate::relay::push_gate::test_relay_url());
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

    /// Every session the WebTransport listener creates reads the shared
    /// [`LiveRelayUrl`]: after a `set` on a clone of the handle, a session
    /// answers the new reserved routing ID and the previous one with 4063 and
    /// stores nothing at either.
    #[tokio::test]
    async fn webtransport_listener_reads_the_shared_relay_url() {
        use super::super::session::DispatchResult;
        use crate::relay::push_gate::RelayUrl;
        use scp_relay_client::{ClientMessage, RelayMessage};
        let old = RelayUrl::new("ws://198.51.100.7:32891/scp/v1").unwrap();
        let new = RelayUrl::new("ws://203.0.113.42:8443/scp/v1").unwrap();
        let live = LiveRelayUrl::new(old.clone());
        let storage = Arc::new(InMemoryBlobStorage::new());
        let mut config = WebTransportListenerConfig::defaults(live.clone());
        config.session_config.delivery_jitter_ms = 0;
        let listener = WebTransportListener::new(
            config,
            Arc::clone(&storage),
            crate::relay::subscription::new_registry(),
            PublishRateLimiter::new(100),
            crate::relay::rate_limit::new_connection_tracker(),
            DidSlotRegistry::new(),
        );
        let mut session =
            listener.create_session(IpAddr::V4(Ipv4Addr::LOCALHOST), CancellationToken::new());
        session.mark_active();
        live.set(new.clone());

        for rid in [new.push_routing_id(), old.push_routing_id()] {
            let reply = session
                .dispatch_message_multi(&ClientMessage::Publish {
                    ref_id: Some("push".to_owned()),
                    routing_id: rid,
                    recipient_hint: None,
                    blob_ttl: 60,
                    blob: vec![0x42; 64],
                })
                .await
                .unwrap();
            assert!(
                matches!(
                    &reply,
                    DispatchResult::Single(RelayMessage::Err { code: 4063, .. })
                ),
                "{reply:?}"
            );
            assert!(storage.query(&rid, None, 100).await.unwrap().is_empty());
        }
    }

    /// §10.7.1 "No blob storage" at the WebTransport listener: a blob stored
    /// at a routing ID while the relay did not reserve it is returned by
    /// neither a QUERY nor a SUBSCRIBE backfill once the handle reserves that
    /// ID as a tier 3 entry's, nor after the handle releases it. Each read
    /// runs in a fresh session.
    #[tokio::test]
    async fn webtransport_listener_reads_no_blob_at_a_current_or_released_reserved_id() {
        use super::super::session::DispatchResult;
        use crate::relay::push_gate::RelayUrl;
        use scp_relay_client::{ClientMessage, RelayMessage};
        let fixture = crate::relay::push_gate::tier3_fixture().unwrap();
        let direct = RelayUrl::new("wss://relay.webtransport.test").unwrap();
        let live = LiveRelayUrl::new(direct.clone());
        let mut config = WebTransportListenerConfig::defaults(live.clone());
        config.session_config.delivery_jitter_ms = 0;
        let listener = WebTransportListener::new(
            config,
            Arc::new(InMemoryBlobStorage::new()),
            crate::relay::subscription::new_registry(),
            PublishRateLimiter::new(100),
            crate::relay::rate_limit::new_connection_tracker(),
            DidSlotRegistry::new(),
        );
        let rid = fixture.entry_a.push_routing_id();
        let blobs = |messages: &[RelayMessage]| {
            messages
                .iter()
                .filter(|m| matches!(m, RelayMessage::Blob { .. }))
                .count()
        };
        let read_blob_counts = || async {
            let mut session =
                listener.create_session(IpAddr::V4(Ipv4Addr::LOCALHOST), CancellationToken::new());
            session.mark_active();
            let queried = match session
                .dispatch_message_multi(&ClientMessage::Query {
                    ref_id: Some("q".to_owned()),
                    routing_id: rid,
                    since: None,
                    limit: None,
                })
                .await
                .unwrap()
            {
                DispatchResult::Multi(messages) => blobs(&messages),
                other => panic!("QUERY returned {other:?}"),
            };
            let backfilled = match session
                .dispatch_message_multi(&ClientMessage::Subscribe {
                    ref_id: Some("s".to_owned()),
                    routing_id: rid,
                    since: Some(0),
                })
                .await
                .unwrap()
            {
                DispatchResult::Subscription { messages, .. } => blobs(&messages),
                other => panic!("SUBSCRIBE returned {other:?}"),
            };
            (queried, backfilled)
        };

        let mut session =
            listener.create_session(IpAddr::V4(Ipv4Addr::LOCALHOST), CancellationToken::new());
        session.mark_active();
        let reply = session
            .dispatch_message_multi(&ClientMessage::Publish {
                ref_id: Some("p".to_owned()),
                routing_id: rid,
                recipient_hint: None,
                blob_ttl: 60,
                blob: vec![0x42; 64],
            })
            .await
            .unwrap();
        assert!(
            matches!(
                &reply,
                DispatchResult::Single(RelayMessage::Ok {
                    blob_id: Some(_),
                    ..
                })
            ),
            "{reply:?}"
        );
        assert_eq!(read_blob_counts().await, (1, 1), "ordinary ID");

        live.set(fixture.live.current());
        assert_eq!(read_blob_counts().await, (0, 0), "current tier 3 ID");

        live.set(direct);
        assert_eq!(read_blob_counts().await, (0, 0), "released tier 3 ID");
    }

    /// §10.7.1 "Tier 3 relays" at the WebTransport listener: with the handle
    /// reserving two bridge entries, a session answers a PUBLISH at either
    /// entry's tier 3 push routing ID with 4063 and stores nothing, and stores
    /// a PUBLISH at the bridge relay's own `"scp-push-registration"` ID.
    #[tokio::test]
    async fn webtransport_listener_intercepts_the_tier3_id_of_a_bridge_entry() {
        use super::super::session::DispatchResult;
        use scp_relay_client::{ClientMessage, RelayMessage};
        let fixture = crate::relay::push_gate::tier3_fixture().unwrap();
        let storage = Arc::new(InMemoryBlobStorage::new());
        let mut config = WebTransportListenerConfig::defaults(fixture.live.clone());
        config.session_config.delivery_jitter_ms = 0;
        let listener = WebTransportListener::new(
            config,
            Arc::clone(&storage),
            crate::relay::subscription::new_registry(),
            PublishRateLimiter::new(100),
            crate::relay::rate_limit::new_connection_tracker(),
            DidSlotRegistry::new(),
        );
        let mut session =
            listener.create_session(IpAddr::V4(Ipv4Addr::LOCALHOST), CancellationToken::new());
        session.mark_active();
        let publish = |rid: [u8; 32]| ClientMessage::Publish {
            ref_id: Some("push".to_owned()),
            routing_id: rid,
            recipient_hint: None,
            blob_ttl: 60,
            blob: vec![0x42; 64],
        };

        for rid in [
            fixture.entry_a.push_routing_id(),
            fixture.entry_b.push_routing_id(),
        ] {
            let reply = session.dispatch_message_multi(&publish(rid)).await.unwrap();
            assert!(
                matches!(
                    &reply,
                    DispatchResult::Single(RelayMessage::Err { code: 4063, .. })
                ),
                "{reply:?}"
            );
            assert!(storage.query(&rid, None, 100).await.unwrap().is_empty());
        }
        let reply = session
            .dispatch_message_multi(&publish(fixture.bridge_own_id))
            .await
            .unwrap();
        assert!(
            matches!(
                &reply,
                DispatchResult::Single(RelayMessage::Ok {
                    blob_id: Some(_),
                    ..
                })
            ),
            "{reply:?}"
        );
        assert_eq!(
            storage
                .query(&fixture.bridge_own_id, None, 100)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    /// PUSH-012 criterion 10 at the WebTransport listener: with push enabled
    /// (the production `KelPushVerifier`) and the handle reserving two bridge
    /// entries, a PUBLISH at either entry's tier 3 push routing ID is answered
    /// with `4060` before signature verification, because no Tier 3 envelope
    /// opener exists yet (§10.7.1 "Tier 3 relays", "Tier 3 envelope"), and the
    /// blob store holds nothing at that ID.
    #[cfg(feature = "push-store")]
    #[tokio::test]
    async fn enabled_webtransport_listener_rejects_a_tier3_publish_with_4060() {
        use super::super::session::DispatchResult;
        use scp_relay_client::{ClientMessage, RelayMessage};
        let fixture = crate::relay::push_gate::tier3_fixture().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(InMemoryBlobStorage::new());
        let mut config = WebTransportListenerConfig::defaults(fixture.live.clone());
        config.session_config.delivery_jitter_ms = 0;
        config.session_config.push = crate::relay::push_gate::PushRole::Enabled(
            crate::relay::push_gate::kel_service_for_tests(dir.path()),
        );
        let listener = WebTransportListener::new(
            config,
            Arc::clone(&storage),
            crate::relay::subscription::new_registry(),
            PublishRateLimiter::new(100),
            crate::relay::rate_limit::new_connection_tracker(),
            DidSlotRegistry::new(),
        );
        let mut session =
            listener.create_session(IpAddr::V4(Ipv4Addr::LOCALHOST), CancellationToken::new());
        session.mark_active();
        for rid in [
            fixture.entry_a.push_routing_id(),
            fixture.entry_b.push_routing_id(),
        ] {
            let publish = ClientMessage::Publish {
                ref_id: Some("push".to_owned()),
                routing_id: rid,
                recipient_hint: None,
                blob_ttl: 60,
                blob: vec![0x42; 64],
            };
            let reply = session.dispatch_message_multi(&publish).await.unwrap();
            assert!(
                matches!(
                    &reply,
                    DispatchResult::Single(RelayMessage::Err { code: 4060, .. })
                ),
                "{reply:?}"
            );
            assert!(storage.query(&rid, None, 100).await.unwrap().is_empty());
        }
    }
}
