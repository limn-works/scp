//! [`QuicAdapter`] -- implements [`TransportAdapter`] for QUIC transport.
//!
//! This adapter translates between the SCP transport API ([`TransportAdapter`])
//! and the QUIC protocol using per-operation bidirectional streams (section 10.14).
//! QUIC replaces WebSocket for native (non-browser) clients, using the same
//! `MessagePack` wire format (ADR-004) with different framing.
//!
//! # Operation Mapping (section 10.14.1)
//!
//! | Transport method | QUIC mapping |
//! |------------------|-------------|
//! | `send` | New bidirectional stream -> send PUBLISH -> receive ACK -> close |
//! | `subscribe` | Long-lived bidirectional stream -> receive BLOBs until close |
//! | `unsubscribe` | Close the subscription's stream (clean FIN) |
//! | `query` | New bidirectional stream -> send QUERY -> results + `query_complete` -> close |
//! | `delete` | New bidirectional stream -> send DELETE -> receive ACK -> close |
//!
//! See section 10.14 in `.docs/specs/10-infrastructure-and-self-hosting.md` and
//! ADR-037 in `.docs/adrs/phase-2.md` for the full specification.

use std::pin::Pin;

use futures::Stream;
use scp_core::envelope::OuterEnvelope;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::error::TransportError;
use crate::native::protocol::{ClientMessage, RelayMessage};
use crate::quic::lifecycle::QuicLifecycleManager;
use crate::quic::streams::{LENGTH_PREFIX_SIZE, MAX_FRAME_SIZE};
use crate::subscription::{MAX_TRANSPORT_SUBSCRIPTIONS, TransportSubscriptionMap};
use crate::traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter, TransportEvent};

/// A boxed, pinned, `Send`-safe future -- the return type for all
/// [`TransportAdapter`] methods to ensure the trait is dyn-compatible.
type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Active subscription state tracked per routing ID.
struct SubscriptionHandle {
    /// Token to cancel the subscription's background read loop.
    cancel: CancellationToken,
}

/// Transport adapter for QUIC (section 10.14).
///
/// Implements [`TransportAdapter`] using per-operation QUIC bidirectional
/// streams via the `quinn` crate. Each SCP operation maps to an independent
/// QUIC stream, eliminating head-of-line blocking and `ref_id` correlation.
///
/// QUIC provides:
/// - **Session resumption (1-RTT)** via session tickets (section 10.14.2).
///   0-RTT early data is intentionally NOT enabled — see [`QuicAdapter::connect_url`].
/// - **Connection migration** when the client's IP address changes.
/// - **Native keepalive** via QUIC PING frames (no application-level PING/PONG).
/// - **Independent streams** per operation (no head-of-line blocking).
///
/// # Construction
///
/// Use [`QuicAdapter::connect`] to establish a QUIC connection to a relay.
///
/// ```rust,ignore
/// use scp_transport::quic::QuicAdapter;
/// use scp_transport::quic::lifecycle::{QuicLifecycleManager, SessionTicketStore};
/// use scp_transport::profile::TransportProfile;
///
/// let store = SessionTicketStore::new();
/// let lifecycle = QuicLifecycleManager::new(TransportProfile::Desktop, store);
/// let adapter = QuicAdapter::connect(addr, "localhost", client_config, lifecycle).await?;
/// ```
#[allow(dead_code)] // lifecycle stored for future reconnect logic
pub struct QuicAdapter {
    /// The underlying QUIC connection.
    connection: RwLock<Option<quinn::Connection>>,

    /// Connection lifecycle manager (session resumption, keepalive, backoff).
    lifecycle: RwLock<QuicLifecycleManager>,

    /// Active subscription handles keyed by routing ID.
    subscriptions: TransportSubscriptionMap<SubscriptionHandle>,
}

impl std::fmt::Debug for QuicAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicAdapter").finish_non_exhaustive()
    }
}

// Static assertion: QuicAdapter must be Send + Sync for dyn TransportAdapter.
#[allow(dead_code, clippy::missing_const_for_fn)]
const fn _assert_quic_adapter_send_sync()
where
    QuicAdapter: Send + Sync,
{
}

impl QuicAdapter {
    /// Creates a new `QuicAdapter` connected to the given relay address.
    ///
    /// # Arguments
    ///
    /// * `relay_addr` -- Socket address of the QUIC relay.
    /// * `server_name` -- TLS server name (SNI) for the connection.
    /// * `client_config` -- Pre-configured quinn `ClientConfig` with TLS and ALPN.
    /// * `lifecycle` -- Lifecycle manager for keepalive, backoff, and session
    ///   resumption.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the QUIC connection
    /// cannot be established.
    pub async fn connect(
        relay_addr: std::net::SocketAddr,
        server_name: &str,
        client_config: quinn::ClientConfig,
        lifecycle: QuicLifecycleManager,
    ) -> Result<Self, TransportError> {
        // Bind the client UDP socket to the address family of the resolved
        // relay. A socket bound to `AF_INET` (IPv4 wildcard) cannot reach an
        // `AF_INET6` destination, so hardcoding the IPv4 wildcard would silently
        // break QUIC for IPv6 / dual-stack relays (the family mismatch surfaces
        // as a connect failure, then WS fallback + QUIC suppression). Mirror the
        // resolved address's family for the ephemeral client bind.
        let bind_addr = match relay_addr {
            std::net::SocketAddr::V4(_) => {
                std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
            }
            std::net::SocketAddr::V6(_) => {
                std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
            }
        };
        let mut endpoint = quinn::Endpoint::client(bind_addr)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        endpoint.set_default_client_config(client_config);

        let connection = endpoint
            .connect(relay_addr, server_name)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        Ok(Self {
            connection: RwLock::new(Some(connection)),
            lifecycle: RwLock::new(lifecycle),
            subscriptions: TransportSubscriptionMap::new(),
        })
    }

    /// Creates a new `QuicAdapter` by resolving a relay URL and building a
    /// QUIC client configuration with Web PKI trust, SCP ALPN, and TLS 1.3
    /// session resumption (1-RTT). 0-RTT early data is intentionally NOT
    /// enabled — see the 0-RTT safety note below.
    ///
    /// This is the URL-based counterpart to [`connect`](Self::connect): it
    /// performs DNS resolution of the relay's host:port, constructs a
    /// non-permissive `rustls::ClientConfig` (see security note below), wires
    /// the lifecycle's [`SessionTicketStore`] for 1-RTT resumption, applies
    /// the lifecycle keepalive, and then delegates to the same connection
    /// path as [`connect`].
    ///
    /// The accepted URL schemes mirror the WebSocket adapter's relay URLs:
    /// `wss://` / `https://` (TLS, Web PKI roots) connect over QUIC normally.
    /// `ws://` / `http://` are **rejected** — QUIC mandates TLS 1.3
    /// (RFC 9001 §4.1), so there is no plaintext QUIC. Plaintext local relays
    /// stay on WebSocket; the [`TransportSelector`](crate::selection::TransportSelector)
    /// only probes QUIC for TLS relays that advertise it.
    ///
    /// # 0-RTT safety (spec §10.14.2)
    ///
    /// This method establishes the connection with the **full 1-RTT
    /// handshake** (`endpoint.connect(...).await`) and never calls
    /// `Connecting::into_0rtt`. No application data is sent as 0-RTT early
    /// data, so non-idempotent operations (PUBLISH, DELETE, UNSUBSCRIBE) are
    /// inherently safe from 0-RTT replay — every operation runs only after the
    /// handshake completes. The wired [`SessionTicketStore`] accelerates the
    /// *handshake* (session resumption) but does not enable early data.
    ///
    /// # Security
    ///
    /// quinn's `platform-verifier` feature is intentionally disabled (it pulls
    /// in a second crypto provider — see the crate `Cargo.toml`). The client
    /// config therefore supplies its **own** root store, built from the
    /// Mozilla Web PKI trust anchors (`webpki-roots`) via
    /// `rustls::ClientConfig::builder_with_provider(ring::default_provider())`.
    /// No accept-all / empty / permissive verifier is ever wired: an untrusted
    /// server certificate fails the handshake closed. If no trust anchors are
    /// available the config build fails rather than connecting insecurely.
    ///
    /// # Arguments
    ///
    /// * `relay_url` -- The relay URL (e.g. `"wss://relay.example.com/scp/v1"`).
    /// * `lifecycle` -- Lifecycle manager supplying the ticket store, keepalive,
    ///   and backoff configuration.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ProtocolError`] if the URL scheme is not a TLS
    /// scheme (e.g. `ws://`), if the host is missing, or if the rustls config
    /// cannot be built. Returns [`TransportError::ConnectionFailed`] if DNS
    /// resolution fails or the QUIC connection cannot be established.
    pub async fn connect_url(
        relay_url: &str,
        lifecycle: QuicLifecycleManager,
    ) -> Result<Self, TransportError> {
        let (host, addr) = resolve_quic_target(relay_url).await?;
        let client_config = build_quic_client_config(lifecycle.ticket_store(), &lifecycle)?;
        Self::connect(addr, &host, client_config, lifecycle).await
    }

    /// Creates a `QuicAdapter` wrapping an existing QUIC connection.
    ///
    /// Useful for testing or when the connection is established externally.
    #[must_use]
    pub fn from_connection(connection: quinn::Connection, lifecycle: QuicLifecycleManager) -> Self {
        Self {
            connection: RwLock::new(Some(connection)),
            lifecycle: RwLock::new(lifecycle),
            subscriptions: TransportSubscriptionMap::new(),
        }
    }

    /// Returns `true` if the adapter has an active QUIC connection.
    pub async fn is_connected(&self) -> bool {
        self.connection.read().await.is_some()
    }

    /// Returns the underlying QUIC connection, if connected.
    async fn get_connection(&self) -> Result<quinn::Connection, TransportError> {
        self.connection
            .read()
            .await
            .clone()
            .ok_or(TransportError::NotConnected)
    }

    /// Writes a `ClientMessage` to a QUIC send stream using length-prefixed
    /// `MessagePack` framing (same format as the listener's `read_client_message`).
    async fn write_client_message(
        send: &mut quinn::SendStream,
        msg: &ClientMessage,
    ) -> Result<(), TransportError> {
        let payload = msg
            .to_bytes()
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        let len = u32::try_from(payload.len()).map_err(|_| {
            TransportError::SendFailed(format!(
                "message too large for length prefix: {} bytes",
                payload.len()
            ))
        })?;
        if len > MAX_FRAME_SIZE {
            return Err(TransportError::SendFailed(format!(
                "message exceeds maximum frame size: {len} > {MAX_FRAME_SIZE}"
            )));
        }

        send.write_all(&len.to_be_bytes())
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;
        send.write_all(&payload)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        Ok(())
    }

    /// Reads a `RelayMessage` from a QUIC receive stream using length-prefixed
    /// `MessagePack` framing (same format as the listener's `write_relay_message`).
    async fn read_relay_message(
        recv: &mut quinn::RecvStream,
    ) -> Result<RelayMessage, TransportError> {
        let mut len_buf = [0u8; LENGTH_PREFIX_SIZE];
        recv.read_exact(&mut len_buf).await.map_err(|e| {
            TransportError::ProtocolError(format!("failed to read length prefix: {e}"))
        })?;

        let msg_len = u32::from_be_bytes(len_buf);
        if msg_len > MAX_FRAME_SIZE {
            return Err(TransportError::ProtocolError(format!(
                "frame length exceeds maximum: {msg_len} > {MAX_FRAME_SIZE}"
            )));
        }
        if msg_len == 0 {
            return Err(TransportError::ProtocolError(
                "received zero-length frame".to_string(),
            ));
        }

        let mut buf = vec![0u8; msg_len as usize];
        recv.read_exact(&mut buf).await.map_err(|e| {
            TransportError::ProtocolError(format!("failed to read message payload: {e}"))
        })?;

        RelayMessage::from_bytes(&buf).map_err(|_| {
            tracing::warn!("relay message deserialization failed");
            TransportError::ProtocolError("invalid relay message".to_owned())
        })
    }
}

impl TransportAdapter for QuicAdapter {
    /// Send an outer envelope via a QUIC bidirectional stream.
    ///
    /// Opens a new bidirectional stream, sends a PUBLISH frame, receives
    /// ACK/ERR, and closes the stream (section 10.14.1).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no active connection,
    /// [`TransportError::SendFailed`] if the operation fails.
    fn send(&self, envelope: &OuterEnvelope) -> BoxFuture<'_, Result<BlobId, TransportError>> {
        let blob_result = envelope.to_bytes();
        let routing_id_vec = envelope.routing_id.clone();
        let recipient_hint_vec = envelope.recipient_hint.clone();
        let blob_ttl = envelope.blob_ttl;

        Box::pin(async move {
            let connection = self.get_connection().await?;

            let blob = blob_result.map_err(|e| TransportError::SendFailed(e.to_string()))?;

            let routing_id: [u8; 32] = routing_id_vec.as_slice().try_into().map_err(|_| {
                TransportError::SendFailed(format!(
                    "invalid routing_id length: expected 32, got {}",
                    routing_id_vec.len()
                ))
            })?;

            let recipient_hint: Option<[u8; 32]> = recipient_hint_vec
                .as_ref()
                .map(|hint| {
                    hint.as_slice().try_into().map_err(|_| {
                        TransportError::SendFailed(format!(
                            "invalid recipient_hint length: expected 32, got {}",
                            hint.len()
                        ))
                    })
                })
                .transpose()?;

            let msg = ClientMessage::Publish {
                ref_id: None,
                routing_id,
                recipient_hint,
                blob_ttl,
                blob,
            };

            let (mut send, mut recv) = connection
                .open_bi()
                .await
                .map_err(|e| TransportError::SendFailed(format!("failed to open stream: {e}")))?;

            Self::write_client_message(&mut send, &msg).await?;
            send.finish()
                .map_err(|e| TransportError::SendFailed(format!("failed to finish stream: {e}")))?;

            let response = Self::read_relay_message(&mut recv).await?;

            match response {
                RelayMessage::Ok {
                    blob_id: Some(id), ..
                } => Ok(BlobId::new(id)),
                RelayMessage::Ok { blob_id: None, .. } => Ok(BlobId::from_sha256(&routing_id_vec)),
                RelayMessage::Err { code, msg, .. } => Err(TransportError::SendFailed(format!(
                    "relay error {code}: {msg}"
                ))),
                _ => Err(TransportError::ProtocolError(
                    "unexpected response to PUBLISH".to_string(),
                )),
            }
        })
    }

    /// Subscribe to envelopes for a given routing ID via a long-lived QUIC stream.
    ///
    /// Opens a long-lived bidirectional stream, sends a SUBSCRIBE frame,
    /// reads the OK response, and returns a stream that yields BLOBs as
    /// [`TransportEvent`]s. The subscription is tracked internally and
    /// can be cancelled via [`unsubscribe`](Self::unsubscribe).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no active connection,
    /// [`TransportError::SubscriptionFailed`] if the relay rejects the subscription.
    fn subscribe(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<SubscriptionStream, TransportError>> {
        let routing_id_bytes = *routing_id.as_bytes();
        Box::pin(async move {
            let connection = self.get_connection().await?;

            // Best-effort pre-IO cap check: avoid opening a QUIC stream +
            // sending SUBSCRIBE when we already know the post-IO insert
            // would reject. The post-IO `insert_or_replace` below is the
            // authoritative gate; this pre-check is a fast-path
            // optimization that narrows the relay-side leak window when
            // the cap is hit. A residual TOCTOU between this check and
            // `insert_or_replace` is acceptable: if the insert nonetheless
            // fails in that window, the error path below finishes the send
            // stream so a conforming relay can release any subscription state
            // gracefully (whether it does is relay-implementation-dependent).
            if !self
                .subscriptions
                .contains(&RoutingId::new(routing_id_bytes))
                && self.subscriptions.len() >= MAX_TRANSPORT_SUBSCRIPTIONS
            {
                return Err(TransportError::SubscriptionFailed(format!(
                    "subscription map full (max {MAX_TRANSPORT_SUBSCRIPTIONS} entries)"
                )));
            }

            let msg = ClientMessage::Subscribe {
                ref_id: None,
                routing_id: routing_id_bytes,
                since,
            };

            let (mut send, mut recv) = connection.open_bi().await.map_err(|e| {
                TransportError::SubscriptionFailed(format!("failed to open stream: {e}"))
            })?;

            // Error paths between open_bi() and successful registration in
            // `self.subscriptions` must call `send.finish()` before returning
            // so the relay sees a graceful FIN rather than a stream RESET.
            // RESET is a hard close; a FIN lets a conforming relay release any
            // subscription state it created. Whether a given relay keys cleanup
            // off the per-stream FIN is relay-implementation-dependent (SCP's
            // own relay cleans up on connection-level close).
            if let Err(e) = Self::write_client_message(&mut send, &msg).await {
                let _ = send.finish();
                return Err(TransportError::SubscriptionFailed(format!(
                    "failed to send SUBSCRIBE: {e}"
                )));
            }
            // Do NOT finish the send stream on the success path -- subscribe
            // stream stays open and is moved into the spawned read loop below.

            // Read the OK/ERR response from the relay.
            let response = match Self::read_relay_message(&mut recv).await {
                Ok(r) => r,
                Err(e) => {
                    let _ = send.finish();
                    return Err(TransportError::SubscriptionFailed(format!(
                        "failed to read SUBSCRIBE response: {e}"
                    )));
                }
            };

            match &response {
                RelayMessage::Ok { .. } => {}
                RelayMessage::Err { code, msg, .. } => {
                    let _ = send.finish();
                    return Err(TransportError::SubscriptionFailed(format!(
                        "relay rejected subscription: {code}: {msg}"
                    )));
                }
                _ => {
                    let _ = send.finish();
                    return Err(TransportError::ProtocolError(
                        "unexpected response to SUBSCRIBE".to_string(),
                    ));
                }
            }

            // Create a cancellation token for this subscription.
            let cancel = CancellationToken::new();
            let cancel_clone = cancel.clone();

            // Store the subscription handle, replacing any previous one for
            // this routing ID (and cancelling the old read loop).
            let new_handle = SubscriptionHandle { cancel };
            match self
                .subscriptions
                .insert_or_replace(RoutingId::new(routing_id_bytes), new_handle)
            {
                Ok(Some(prev)) => prev.cancel.cancel(),
                Ok(None) => {}
                Err(e) => {
                    // Registration failed after IO (TOCTOU vs the pre-IO cap
                    // check above); finish the send stream so the relay sees a
                    // graceful FIN rather than a RESET, allowing a conforming
                    // relay to release any subscription state it just created
                    // (whether it does is relay-implementation-dependent).
                    let _ = send.finish();
                    return Err(TransportError::SubscriptionFailed(format!(
                        "subscription map full: {e}"
                    )));
                }
            }

            // Create a channel for the subscription stream.
            let (tx, rx) = tokio::sync::mpsc::channel::<TransportEvent>(256);

            // Spawn a background task to read BLOBs from the QUIC stream
            // and forward them as `TransportEvent`s.
            tokio::spawn(run_subscribe_read_loop(
                send,
                recv,
                cancel_clone,
                routing_id_bytes,
                tx,
            ));

            let stream = QuicSubscriptionStream { rx };
            Ok(Box::pin(stream) as SubscriptionStream)
        })
    }

    /// Unsubscribe from a routing ID by cancelling the subscription's
    /// background read loop, which closes the QUIC stream with a clean FIN.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no active connection.
    fn unsubscribe(&self, routing_id: &RoutingId) -> BoxFuture<'_, Result<(), TransportError>> {
        let routing_id_bytes = *routing_id.as_bytes();
        Box::pin(async move {
            // Verify we have a connection.
            let _connection = self.get_connection().await?;

            if let Some(h) = self.subscriptions.remove(&RoutingId::new(routing_id_bytes)) {
                h.cancel.cancel();
            }
            Ok(())
        })
    }

    /// One-shot query for stored envelopes via a QUIC bidirectional stream.
    ///
    /// Opens a new bidirectional stream, sends a QUERY frame, receives
    /// results + `query_complete`, and closes the stream (section 10.14.1).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no active connection,
    /// [`TransportError::ProtocolError`] for protocol-level errors.
    fn query(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, TransportError>> {
        let routing_id_bytes = *routing_id.as_bytes();
        Box::pin(async move {
            let connection = self.get_connection().await?;

            let msg = ClientMessage::Query {
                ref_id: None,
                routing_id: routing_id_bytes,
                since,
                limit: None,
            };

            let (mut send, mut recv) = connection
                .open_bi()
                .await
                .map_err(|e| TransportError::SendFailed(format!("failed to open stream: {e}")))?;

            Self::write_client_message(&mut send, &msg).await?;
            send.finish()
                .map_err(|e| TransportError::SendFailed(format!("failed to finish stream: {e}")))?;

            // Collect BLOBs until we receive EVENT(query_complete) or the stream closes.
            // SEC-007: cap results to prevent unbounded memory growth from a
            // malicious or misconfigured relay streaming excessive responses.
            let mut envelopes = Vec::new();
            #[allow(clippy::items_after_statements)]
            const MAX_QUERY_RESULTS: usize = 1_000;
            while let Ok(relay_msg) = Self::read_relay_message(&mut recv).await {
                match relay_msg {
                    RelayMessage::Blob { blob, .. } => {
                        if envelopes.len() >= MAX_QUERY_RESULTS {
                            return Err(TransportError::ProtocolError(format!(
                                "query response exceeded maximum result count ({MAX_QUERY_RESULTS})"
                            )));
                        }
                        match OuterEnvelope::from_bytes(&blob) {
                            Ok(envelope) => envelopes.push(envelope),
                            Err(_) => {
                                // The blob is attacker-controlled. Some serde
                                // codecs include byte excerpts in their
                                // `Display`; do not include the inner error.
                                return Err(TransportError::ProtocolError(
                                    "failed to deserialize envelope from blob".to_string(),
                                ));
                            }
                        }
                    }
                    RelayMessage::Event { event_type, .. } if event_type == "query_complete" => {
                        break;
                    }
                    RelayMessage::Err { code, msg, .. } => {
                        return Err(TransportError::ProtocolError(format!(
                            "relay error {code}: {msg}"
                        )));
                    }
                    _ => {
                        // Skip unknown events.
                    }
                }
            }

            Ok(envelopes)
        })
    }

    /// Request deletion of a blob via a QUIC bidirectional stream.
    ///
    /// Opens a new bidirectional stream, sends a DELETE frame, receives
    /// ACK/ERR, and closes the stream (section 10.14.1).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no active connection,
    /// [`TransportError::SendFailed`] if the delete request fails.
    fn delete(&self, blob_id: &BlobId) -> BoxFuture<'_, Result<(), TransportError>> {
        let blob_id_bytes = *blob_id.as_bytes();
        Box::pin(async move {
            let connection = self.get_connection().await?;

            let msg = ClientMessage::Delete {
                ref_id: None,
                blob_id: blob_id_bytes,
            };

            let (mut send, mut recv) = connection
                .open_bi()
                .await
                .map_err(|e| TransportError::SendFailed(format!("failed to open stream: {e}")))?;

            Self::write_client_message(&mut send, &msg).await?;
            send.finish()
                .map_err(|e| TransportError::SendFailed(format!("failed to finish stream: {e}")))?;

            let response = Self::read_relay_message(&mut recv).await?;

            match response {
                RelayMessage::Err { code, msg, .. } => Err(TransportError::SendFailed(format!(
                    "relay error {code}: {msg}"
                ))),
                // Best-effort: treat all non-error responses as success.
                _ => Ok(()),
            }
        })
    }
}

/// Parses a relay URL and resolves its host:port to a [`SocketAddr`].
///
/// Only TLS schemes are accepted: `wss://` and `https://`. Plaintext schemes
/// (`ws://`, `http://`) are rejected because QUIC mandates TLS 1.3
/// (RFC 9001 §4.1) — there is no plaintext QUIC transport. Scheme matching is
/// case-insensitive per RFC 3986 §3.1. When the URL omits a port, the QUIC
/// default of `443` is used (QUIC runs over UDP/443 alongside HTTPS).
///
/// Returns the `(server_name, socket_addr)` pair: the server name is the host
/// (for TLS SNI / certificate verification) and the socket address is the
/// resolved UDP target for the QUIC endpoint.
///
/// [`SocketAddr`]: std::net::SocketAddr
async fn resolve_quic_target(
    relay_url: &str,
) -> Result<(String, std::net::SocketAddr), TransportError> {
    // Normalize scheme to lowercase (RFC 3986 §3.1: scheme is case-insensitive).
    let lower = relay_url.to_ascii_lowercase();
    let host_and_path = if let Some(stripped) = lower.strip_prefix("wss://") {
        stripped
    } else if let Some(stripped) = lower.strip_prefix("https://") {
        stripped
    } else {
        return Err(TransportError::ProtocolError(format!(
            "QUIC requires a TLS relay URL (wss:// or https://), got: {relay_url}"
        )));
    };

    // Strip any path/query, keeping only the authority (host[:port]).
    let authority = host_and_path
        .split('/')
        .next()
        .unwrap_or(host_and_path)
        .split('?')
        .next()
        .unwrap_or(host_and_path);

    if authority.is_empty() {
        return Err(TransportError::ProtocolError(
            "QUIC relay URL has an empty host".to_owned(),
        ));
    }

    // Strip userinfo (RFC 3986 §3.2.1) before host extraction to prevent a
    // bypass via `wss://user:pass@evil.com` — the `@` separates userinfo from
    // the authority, so the real connection target is `evil.com`. The native /
    // WebSocket path strips userinfo for the same reason (see
    // `relay::connection::is_loopback`); mirror it here for defense-in-depth.
    let authority = authority
        .rfind('@')
        .map_or(authority, |at_pos| &authority[at_pos + 1..]);

    if authority.is_empty() {
        return Err(TransportError::ProtocolError(
            "QUIC relay URL has an empty host".to_owned(),
        ));
    }

    // Split host:port. IPv6 literals are bracketed (`[::1]:443`); handle them
    // by locating the closing bracket before scanning for the port colon.
    let (host, port) = parse_host_port(authority)?;

    // Resolve to a concrete socket address via DNS (or direct IP parse).
    let resolved = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| {
            TransportError::ConnectionFailed(format!("DNS resolution failed for {host}: {e}"))
        })?
        .next()
        .ok_or_else(|| {
            TransportError::ConnectionFailed(format!("no addresses resolved for host: {host}"))
        })?;

    Ok((host, resolved))
}

/// Splits an authority (`host`, `host:port`, `[ipv6]`, or `[ipv6]:port`) into
/// its host and port components. Defaults to port `443` (QUIC over UDP/443)
/// when no port is present.
fn parse_host_port(authority: &str) -> Result<(String, u16), TransportError> {
    /// QUIC default port — runs over UDP/443 alongside HTTPS.
    const DEFAULT_QUIC_PORT: u16 = 443;

    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: `[addr]` or `[addr]:port`.
        let close = rest.find(']').ok_or_else(|| {
            TransportError::ProtocolError(format!(
                "malformed IPv6 host in QUIC relay URL: {authority}"
            ))
        })?;
        let host = rest[..close].to_owned();
        let after = &rest[close + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>().map_err(|_| {
                TransportError::ProtocolError(format!(
                    "invalid port in QUIC relay URL: {authority}"
                ))
            })?
        } else {
            DEFAULT_QUIC_PORT
        };
        return Ok((host, port));
    }

    // IPv4 / DNS host: split on the single ':' if present.
    match authority.rsplit_once(':') {
        Some((host, port_str)) => {
            let port = port_str.parse::<u16>().map_err(|_| {
                TransportError::ProtocolError(format!(
                    "invalid port in QUIC relay URL: {authority}"
                ))
            })?;
            Ok((host.to_owned(), port))
        }
        None => Ok((authority.to_owned(), DEFAULT_QUIC_PORT)),
    }
}

/// Builds a quinn `ClientConfig` for connecting to a TLS QUIC relay.
///
/// The TLS config is built via
/// `rustls::ClientConfig::builder_with_provider(ring::default_provider())`
/// with a root store populated from the Mozilla Web PKI trust anchors
/// (`webpki-roots`). This is a **non-permissive** verifier: untrusted server
/// certificates fail the handshake. quinn's `platform-verifier` is disabled
/// (see crate `Cargo.toml`), so this explicit root store is the trust anchor.
///
/// The lifecycle's [`SessionTicketStore`] is wired as the rustls
/// `ClientSessionStore` so resumed connections reuse session tickets for a
/// faster (1-RTT) handshake. 0-RTT early data is **not** enabled here — see
/// [`QuicAdapter::connect_url`] for the 0-RTT safety rationale.
///
/// # Errors
///
/// Returns [`TransportError::ProtocolError`] if the rustls protocol-version or
/// QUIC-config construction fails.
fn build_quic_client_config(
    ticket_store: &crate::quic::lifecycle::SessionTicketStore,
    lifecycle: &QuicLifecycleManager,
) -> Result<quinn::ClientConfig, TransportError> {
    use std::sync::Arc;

    // WebPKI (Mozilla) root trust anchors. This is the same trust set a
    // browser/OS would use for HTTPS — no custom or permissive verifier.
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    // Build the rustls client config on the ring provider (quinn is ring-only;
    // see crate Cargo.toml). builder_with_provider keeps the process-default
    // crypto provider unambiguous.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            TransportError::ProtocolError(format!("failed to set TLS protocol versions: {e}"))
        })?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // SCP ALPN — the relay negotiates the SCP application protocol.
    tls_config.alpn_protocols = vec![crate::quic::listener::SCP_ALPN.to_vec()];

    // Wire the session ticket store for 1-RTT resumption. The store is
    // Arc-backed internally, so cloning shares the same ticket state used by
    // the lifecycle manager.
    tls_config.resumption =
        rustls::client::Resumption::store(Arc::new(ticket_store.clone()) as Arc<_>);

    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|e| {
            TransportError::ProtocolError(format!("failed to build QUIC client config: {e}"))
        })?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

    // Apply lifecycle keepalive (QUIC-native PING frames replace WS PING/PONG).
    let mut transport_config = quinn::TransportConfig::default();
    lifecycle.configure_transport(&mut transport_config);
    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}

/// Stream adapter that converts QUIC subscription messages (received via a
/// tokio channel) into [`TransportEvent`]s.
struct QuicSubscriptionStream {
    rx: tokio::sync::mpsc::Receiver<TransportEvent>,
}

impl Stream for QuicSubscriptionStream {
    type Item = TransportEvent;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

/// Background read loop for a QUIC subscription stream.
///
/// Reads `RelayMessage`s from `recv`, maps them to [`TransportEvent`]s via
/// [`map_subscribe_relay_message`], and forwards them on `tx` until the
/// subscription is cancelled, the stream closes, or the receiver is dropped.
/// On cancellation the send side is finished so the relay sees a graceful FIN.
async fn run_subscribe_read_loop(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    cancel: CancellationToken,
    routing_id_bytes: [u8; 32],
    tx: tokio::sync::mpsc::Sender<TransportEvent>,
) {
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                // Clean shutdown: finish the send side to signal
                // the relay that we are done.
                let _ = send.finish();
                break;
            }
            result = QuicAdapter::read_relay_message(&mut recv) => {
                if let Ok(relay_msg) = result {
                    let Some(event) = map_subscribe_relay_message(
                        relay_msg,
                        &routing_id_bytes,
                    ) else {
                        continue;
                    };
                    if tx.send(event).await.is_err() {
                        // Receiver dropped, stop reading.
                        break;
                    }
                } else {
                    // Stream closed or error -- subscription terminated.
                    let _ = tx
                        .send(TransportEvent::Terminated {
                            reason: "QUIC stream closed".to_string(),
                        })
                        .await;
                    break;
                }
            }
        }
    }
}

/// Maps a `RelayMessage` received on a QUIC subscribe stream to the
/// corresponding `TransportEvent`. Returns `None` for messages the
/// subscriber should ignore (BLOBs with mismatched `routing_id` from a
/// non-conformant relay, unknown event types, OK/Pong/Bridge messages).
fn map_subscribe_relay_message(
    relay_msg: RelayMessage,
    expected_routing_id: &[u8; 32],
) -> Option<TransportEvent> {
    // Defense against a non-conformant relay that pushes BLOBs from
    // another routing_id into this subscription's dedicated stream.
    if let RelayMessage::Blob {
        routing_id: blob_rid,
        ..
    } = &relay_msg
        && blob_rid != expected_routing_id
    {
        tracing::debug!(
            expected = ?expected_routing_id,
            received = ?blob_rid,
            "QUIC subscribe stream received BLOB with mismatched routing_id; dropping"
        );
        return None;
    }
    match relay_msg {
        RelayMessage::Blob { blob, .. } => Some(OuterEnvelope::from_bytes(&blob).map_or_else(
            |_| {
                TransportEvent::Error(TransportError::ProtocolError(
                    "failed to deserialize envelope from blob".to_string(),
                ))
            },
            TransportEvent::Envelope,
        )),
        RelayMessage::Event { event_type, .. } => match event_type.as_str() {
            "backfill_complete" => Some(TransportEvent::BackfillComplete),
            _ => None,
        },
        RelayMessage::Err { code, msg, .. } => Some(TransportEvent::Error(
            TransportError::ProtocolError(format!("relay error {code}: {msg}")),
        )),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]
mod tests {
    use std::time::Duration;

    use futures::StreamExt;
    use scp_core::envelope::create_outer_envelope;

    use super::*;
    use crate::profile::TransportProfile;
    // The QUIC test harness (listener + matching client) is shared with the
    // out-of-crate conformance/migration integration tests; see
    // `crate::quic::test_support` for why it lives in `src/`.
    use crate::quic::test_support::{connect_adapter, start_test_listener, test_lifecycle};

    fn test_envelope() -> OuterEnvelope {
        create_outer_envelope(&[0xAA; 32], None, 3600, vec![0x01, 0x02, 0x03]).unwrap()
    }

    fn test_envelope_with_routing(routing_id: &[u8; 32]) -> OuterEnvelope {
        create_outer_envelope(routing_id, None, 3600, vec![0x01, 0x02, 0x03]).unwrap()
    }

    // -----------------------------------------------------------------------
    // Unit tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn adapter_is_connected_after_connect() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();
        let adapter = connect_adapter(addr, &certs).await;

        assert!(adapter.is_connected().await);

        handle.shutdown();
    }

    // -----------------------------------------------------------------------
    // Integration tests: send
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn send_roundtrip_returns_blob_id() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();
        let adapter = connect_adapter(addr, &certs).await;

        let envelope = test_envelope();
        let result = adapter.send(&envelope).await;
        assert!(result.is_ok(), "send should succeed: {result:?}");

        let blob_id = result.unwrap();
        // blob_id should be a valid 32-byte hash.
        assert_ne!(*blob_id.as_bytes(), [0u8; 32]);

        handle.shutdown();
    }

    // -----------------------------------------------------------------------
    // Integration tests: subscribe + receive
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn subscribe_and_receive_published_blob() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();

        let routing_id_bytes = [0x42; 32];
        let routing_id = RoutingId::new(routing_id_bytes);

        // Connect subscriber.
        let sub_adapter = connect_adapter(addr, &certs).await;
        let mut stream = sub_adapter
            .subscribe(&routing_id, None)
            .await
            .expect("subscribe should succeed");

        // Give subscription time to register.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect a publisher and publish.
        let pub_adapter = connect_adapter(addr, &certs).await;
        let envelope = test_envelope_with_routing(&routing_id_bytes);
        let _blob_id = pub_adapter
            .send(&envelope)
            .await
            .expect("send should succeed");

        // Read the delivered envelope from the subscription stream.
        let event = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("timed out waiting for subscription event")
            .expect("stream should not be empty");

        assert!(
            matches!(event, TransportEvent::Envelope(_)),
            "expected Envelope event, got {event:?}"
        );

        handle.shutdown();
    }

    // -----------------------------------------------------------------------
    // Integration tests: unsubscribe
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unsubscribe_closes_subscription_stream() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();

        let routing_id_bytes = [0x43; 32];
        let routing_id = RoutingId::new(routing_id_bytes);

        let adapter = connect_adapter(addr, &certs).await;
        let mut stream = adapter
            .subscribe(&routing_id, None)
            .await
            .expect("subscribe should succeed");

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Unsubscribe.
        adapter
            .unsubscribe(&routing_id)
            .await
            .expect("unsubscribe should succeed");

        // The stream should eventually terminate.
        let result = tokio::time::timeout(Duration::from_secs(2), stream.next()).await;
        match result {
            Ok(Some(TransportEvent::Terminated { .. }) | None) | Err(_) => {
                // Expected: stream ended, terminated event, or timeout.
                // All are valid outcomes after unsubscribe.
            }
            Ok(Some(other)) => {
                // Some other event before termination is acceptable
                // (e.g., a race with a pending message).
                tracing::debug!("received event after unsubscribe: {other:?}");
            }
        }

        handle.shutdown();
    }

    #[tokio::test]
    async fn subscribe_twice_to_same_routing_id_replaces_previous() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();

        let routing_id_bytes = [0x4A; 32];
        let routing_id = RoutingId::new(routing_id_bytes);

        let adapter = connect_adapter(addr, &certs).await;

        // First subscription.
        let mut first_stream = adapter
            .subscribe(&routing_id, None)
            .await
            .expect("first subscribe should succeed");

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Second subscription for the same routing ID. The previous
        // subscription's read loop must be cancelled and its stream
        // terminated; the new stream is the one that should receive
        // subsequent messages.
        let mut second_stream = adapter
            .subscribe(&routing_id, None)
            .await
            .expect("second subscribe should succeed");

        // The first stream's background read loop was cancelled, which
        // closes its forwarding channel. It either yields a Terminated
        // event or simply ends (None). Either is acceptable.
        let first_outcome = tokio::time::timeout(Duration::from_secs(2), first_stream.next()).await;
        match first_outcome {
            Ok(Some(TransportEvent::Terminated { .. }) | None) => {
                // Expected.
            }
            Ok(Some(other)) => panic!("first stream yielded unexpected event: {other:?}"),
            Err(elapsed) => panic!("first stream did not terminate within 2s: {elapsed}"),
        }

        // Publish on this routing ID and confirm the second stream
        // receives the envelope.
        let pub_adapter = connect_adapter(addr, &certs).await;
        let envelope = test_envelope_with_routing(&routing_id_bytes);
        pub_adapter
            .send(&envelope)
            .await
            .expect("publish should succeed");

        let event = tokio::time::timeout(Duration::from_secs(5), second_stream.next())
            .await
            .expect("timed out waiting for second-stream event")
            .expect("second stream should not be empty");
        assert!(
            matches!(event, TransportEvent::Envelope(_)),
            "expected Envelope on second stream, got {event:?}"
        );

        handle.shutdown();
    }

    // -----------------------------------------------------------------------
    // Integration tests: query
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn query_returns_published_envelope() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();

        let routing_id_bytes = [0x44; 32];
        let routing_id = RoutingId::new(routing_id_bytes);

        let adapter = connect_adapter(addr, &certs).await;

        // Publish an envelope.
        let envelope = test_envelope_with_routing(&routing_id_bytes);
        adapter.send(&envelope).await.expect("send should succeed");

        // Query for it.
        let results = adapter
            .query(&routing_id, None)
            .await
            .expect("query should succeed");

        assert!(
            !results.is_empty(),
            "query should return at least one envelope"
        );

        handle.shutdown();
    }

    // -----------------------------------------------------------------------
    // Integration tests: delete
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn delete_returns_ok() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();
        let adapter = connect_adapter(addr, &certs).await;

        let blob_id = BlobId::new([0xDD; 32]);
        let result = adapter.delete(&blob_id).await;
        assert!(result.is_ok(), "delete should succeed: {result:?}");

        handle.shutdown();
    }

    // -----------------------------------------------------------------------
    // Integration tests: reconnect backoff
    // -----------------------------------------------------------------------

    #[test]
    fn reconnect_backoff_follows_profile_range() {
        use crate::quic::lifecycle::ReconnectBackoff;

        // Desktop profile: 1s min, 30s max.
        let mut backoff = ReconnectBackoff::from_profile(&TransportProfile::Desktop).unwrap();
        let delay = backoff.next_delay();
        // First delay should be >= 1s (min) and <= 1.25s (min + 25% jitter).
        assert!(
            delay >= Duration::from_secs(1),
            "desktop first delay too short: {delay:?}"
        );
        assert!(
            delay <= Duration::from_millis(1250),
            "desktop first delay too long: {delay:?}"
        );

        // Mobile profile: 5s min, 60s max.
        let mut backoff = ReconnectBackoff::from_profile(&TransportProfile::Mobile).unwrap();
        let delay = backoff.next_delay();
        assert!(
            delay >= Duration::from_secs(5),
            "mobile first delay too short: {delay:?}"
        );
        assert!(
            delay <= Duration::from_millis(6250),
            "mobile first delay too long: {delay:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Integration tests: subscribe with backfill
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn subscribe_with_backfill_delivers_stored_blobs() {
        let (handle, addr, certs, _storage, _subs) = start_test_listener();

        let routing_id_bytes = [0x45; 32];
        let routing_id = RoutingId::new(routing_id_bytes);

        let adapter = connect_adapter(addr, &certs).await;

        // Publish an envelope first.
        let envelope = test_envelope_with_routing(&routing_id_bytes);
        adapter.send(&envelope).await.expect("send should succeed");

        // Subscribe with since=0 to trigger backfill.
        let mut stream = adapter
            .subscribe(&routing_id, Some(0))
            .await
            .expect("subscribe should succeed");

        // Should receive the backfilled blob.
        let event = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("timed out waiting for backfill blob")
            .expect("stream should not be empty");

        assert!(
            matches!(event, TransportEvent::Envelope(_)),
            "expected Envelope event from backfill, got {event:?}"
        );

        // Should receive backfill_complete.
        let event = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("timed out waiting for backfill_complete")
            .expect("stream should not be empty");

        assert!(
            matches!(event, TransportEvent::BackfillComplete),
            "expected BackfillComplete event, got {event:?}"
        );

        handle.shutdown();
    }

    // -----------------------------------------------------------------------
    // Edge case: not connected
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn operations_on_disconnected_adapter_fail() {
        // Create an adapter with no connection by connecting and then
        // manually clearing the connection.
        let (handle, addr, certs, _storage, _subs) = start_test_listener();
        let adapter = connect_adapter(addr, &certs).await;

        // Close the underlying connection.
        {
            let mut conn = adapter.connection.write().await;
            if let Some(c) = conn.take() {
                c.close(0u32.into(), b"test disconnect");
            }
        }

        let envelope = test_envelope();
        let result = adapter.send(&envelope).await;
        assert!(
            matches!(result, Err(TransportError::NotConnected)),
            "expected NotConnected, got {result:?}"
        );

        let routing_id = RoutingId::new([0xFF; 32]);
        let sub_result = adapter.subscribe(&routing_id, None).await;
        assert!(
            sub_result.is_err(),
            "expected subscribe to fail on disconnected adapter"
        );

        let result = adapter.query(&routing_id, None).await;
        assert!(
            matches!(result, Err(TransportError::NotConnected)),
            "expected NotConnected, got {result:?}"
        );

        let result = adapter.delete(&BlobId::new([0xFF; 32])).await;
        assert!(
            matches!(result, Err(TransportError::NotConnected)),
            "expected NotConnected, got {result:?}"
        );

        handle.shutdown();
    }

    // -----------------------------------------------------------------------
    // Routing-id mismatch defense (unit tests on the read-loop helper)
    // -----------------------------------------------------------------------

    /// A BLOB whose `routing_id` does not match the dedicated subscribe
    /// stream's expected `routing_id` is silently dropped.
    #[test]
    fn map_subscribe_relay_message_drops_blob_with_mismatched_routing_id() {
        let expected = [0xAAu8; 32];
        let mismatched = [0xBBu8; 32];

        // Build a well-formed OuterEnvelope so the deserialization path
        // would succeed if the message were forwarded; the test must
        // confirm we drop BEFORE deserialization.
        let envelope = create_outer_envelope(&mismatched, None, 3600, vec![1, 2, 3]).unwrap();
        let blob = envelope.to_bytes().unwrap();
        let msg = RelayMessage::Blob {
            routing_id: mismatched,
            blob_id: [0xCCu8; 32],
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob,
        };

        let result = map_subscribe_relay_message(msg, &expected);
        assert!(
            result.is_none(),
            "BLOB with mismatched routing_id must be dropped, got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // connect_url: client config trust (non-permissive verifier)
    // -----------------------------------------------------------------------

    /// The production client config built for `connect_url` uses the Web PKI
    /// root store, NOT an accept-all verifier. Connecting to a relay that
    /// presents an untrusted self-signed certificate MUST fail the handshake.
    ///
    /// This proves no permissive/accept-all verifier is wired: a self-signed
    /// cert (untrusted by the Mozilla root bundle) is rejected. If a permissive
    /// verifier were used, the handshake would succeed and this test would fail.
    #[tokio::test]
    async fn connect_url_rejects_untrusted_self_signed_cert() {
        // Start a QUIC listener with a self-signed cert (untrusted by Web PKI).
        let (handle, addr, _certs, _storage, _subs) = start_test_listener();

        // Build the *production* client config (Web PKI roots), the same one
        // connect_url uses. Bypass DNS resolution by connecting to the bound
        // loopback addr directly with QuicAdapter::connect.
        let lifecycle = test_lifecycle();
        let client_config = super::build_quic_client_config(lifecycle.ticket_store(), &lifecycle)
            .expect("client config should build");

        // The relay's self-signed cert is NOT in the Web PKI root store, so the
        // TLS handshake must fail. Use "localhost" as the SNI (the cert's name)
        // to isolate the failure to trust, not name mismatch.
        let result = QuicAdapter::connect(addr, "localhost", client_config, test_lifecycle()).await;

        assert!(
            result.is_err(),
            "connecting with the Web PKI client config to an untrusted self-signed \
             relay MUST fail — a permissive verifier would have accepted it"
        );

        handle.shutdown();
    }

    /// `connect_url` rejects plaintext schemes: QUIC mandates TLS 1.3, so
    /// `ws://` / `http://` have no QUIC form and must error before any IO.
    #[tokio::test]
    async fn connect_url_rejects_plaintext_scheme() {
        let lifecycle = test_lifecycle();
        let err = QuicAdapter::connect_url("ws://127.0.0.1:9000/scp/v1", lifecycle)
            .await
            .expect_err("ws:// must be rejected for QUIC");
        assert!(
            matches!(err, TransportError::ProtocolError(_)),
            "expected ProtocolError for plaintext scheme, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // IPv6 / dual-stack: client endpoint must bind to the relay's address family
    // -----------------------------------------------------------------------

    /// The client endpoint must bind to the *same address family* as the
    /// resolved relay. A socket bound to the IPv4 wildcard cannot reach an
    /// IPv6 destination, which would surface as a connect failure and silently
    /// disable QUIC for IPv6 / dual-stack relays.
    ///
    /// This connects to a dead `[::1]` port. The expectation is a *connection*
    /// failure from the handshake never completing (no listener), NOT a bind /
    /// address-family error. If the endpoint were still bound to IPv4, quinn
    /// would reject the IPv6 destination at `endpoint.connect()` with an
    /// "invalid remote address" / family-mismatch error before any handshake —
    /// proving the bug. A clean timeout/connection error proves the socket is
    /// IPv6-capable.
    #[tokio::test]
    async fn connect_binds_ipv6_for_ipv6_relay() {
        use std::net::{Ipv6Addr, SocketAddr};

        // A dead loopback IPv6 target: a port nothing is listening on.
        let relay_addr = SocketAddr::from((Ipv6Addr::LOCALHOST, 1));

        let lifecycle = test_lifecycle();
        let client_config = super::build_quic_client_config(lifecycle.ticket_store(), &lifecycle)
            .expect("client config should build");

        // Bound the time: a missing listener means the handshake never
        // completes, so cap the wait so the test can assert on the outcome.
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            QuicAdapter::connect(relay_addr, "localhost", client_config, test_lifecycle()),
        )
        .await;

        match result {
            // Handshake to a dead IPv6 port never completed within the bound:
            // the socket *was* IPv6-capable and tried to reach the target.
            // A cross-family bind would have failed synchronously, well under
            // the timeout, so a timeout here proves the IPv6 bind worked.
            Err(_elapsed) => {}
            // Connect returned an error. It MUST be a connection-level failure
            // (handshake/transport), NOT an address-family / bind error.
            Ok(Err(TransportError::ConnectionFailed(msg))) => {
                let lower = msg.to_ascii_lowercase();
                assert!(
                    !(lower.contains("address family")
                        || lower.contains("invalid remote address")
                        || lower.contains("family")),
                    "connect failed with an address-family/bind error, meaning the \
                     client endpoint was NOT bound IPv6-capable: {msg}"
                );
            }
            Ok(Err(other)) => panic!("unexpected error variant for dead IPv6 target: {other:?}"),
            Ok(Ok(_)) => panic!("connect unexpectedly succeeded against a dead [::1] port"),
        }
    }

    // -----------------------------------------------------------------------
    // resolve_quic_target: userinfo stripping (RFC 3986 §3.2.1 bypass defense)
    // -----------------------------------------------------------------------

    /// `resolve_quic_target` must strip userinfo (`user:pass@`) before host
    /// extraction so a URL like `wss://user@host` connects to `host`, not to a
    /// host smuggled in the userinfo. Mirrors the WebSocket path's defense.
    ///
    /// Resolving `wss://user:pass@[::1]:8443/scp` must yield `[::1]:8443`. If
    /// userinfo were not stripped, `parse_host_port` would see `user:pass@[::1]`
    /// and either fail or resolve the wrong host.
    #[tokio::test]
    async fn resolve_quic_target_strips_userinfo() {
        let (host, addr) = super::resolve_quic_target("wss://user:pass@[::1]:8443/scp/v1")
            .await
            .expect("userinfo-bearing IPv6 URL should resolve to the bracketed host");

        assert_eq!(host, "::1", "host must be the authority host, not userinfo");
        assert!(addr.is_ipv6(), "resolved addr must be IPv6: {addr}");
        assert_eq!(addr.port(), 8443, "port must come from the authority");
        assert_eq!(
            addr,
            std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 8443)),
            "must resolve to [::1]:8443 after stripping userinfo"
        );
    }

    /// IPv4 userinfo form: `wss://user@127.0.0.1:9443` resolves to
    /// `127.0.0.1:9443`, not to a userinfo-smuggled host.
    #[tokio::test]
    async fn resolve_quic_target_strips_userinfo_ipv4() {
        let (host, addr) = super::resolve_quic_target("wss://user@127.0.0.1:9443/scp")
            .await
            .expect("userinfo-bearing IPv4 URL should resolve to the authority host");

        assert_eq!(host, "127.0.0.1");
        assert_eq!(
            addr,
            std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 9443))
        );
    }

    /// `backfill_complete` events propagate; unknown event types are dropped.
    #[test]
    fn map_subscribe_relay_message_event_kinds() {
        let expected = [0xAAu8; 32];
        let backfill = RelayMessage::Event {
            ref_id: None,
            event_type: "backfill_complete".to_string(),
        };
        assert!(matches!(
            map_subscribe_relay_message(backfill, &expected),
            Some(TransportEvent::BackfillComplete)
        ));

        let unknown = RelayMessage::Event {
            ref_id: None,
            event_type: "made_up_event".to_string(),
        };
        assert!(map_subscribe_relay_message(unknown, &expected).is_none());
    }
}
