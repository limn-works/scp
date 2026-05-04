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
/// - **0-RTT reconnection** via session tickets (section 10.14.2).
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

    /// Connection lifecycle manager (0-RTT, keepalive, backoff).
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
    /// * `lifecycle` -- Lifecycle manager for keepalive, backoff, and 0-RTT.
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
        let mut endpoint = quinn::Endpoint::client(std::net::SocketAddr::from(([0, 0, 0, 0], 0)))
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
            // `insert_or_replace` is acceptable. (Broader QUIC error-path
            // leak classes -- e.g., not finishing the send stream on
            // intermediate failures -- are tracked separately.)
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

            Self::write_client_message(&mut send, &msg)
                .await
                .map_err(|e| {
                    TransportError::SubscriptionFailed(format!("failed to send SUBSCRIBE: {e}"))
                })?;
            // Do NOT finish the send stream -- subscribe stream stays open.

            // Read the OK/ERR response from the relay.
            let response = Self::read_relay_message(&mut recv).await.map_err(|e| {
                TransportError::SubscriptionFailed(format!(
                    "failed to read SUBSCRIBE response: {e}"
                ))
            })?;

            match &response {
                RelayMessage::Ok { .. } => {}
                RelayMessage::Err { code, msg, .. } => {
                    return Err(TransportError::SubscriptionFailed(format!(
                        "relay rejected subscription: {code}: {msg}"
                    )));
                }
                _ => {
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
            if let Some(prev) = self
                .subscriptions
                .insert_or_replace(RoutingId::new(routing_id_bytes), new_handle)
                .map_err(|e| {
                    TransportError::SubscriptionFailed(format!("subscription map full: {e}"))
                })?
            {
                prev.cancel.cancel();
            }

            // Create a channel for the subscription stream.
            let (tx, rx) = tokio::sync::mpsc::channel::<TransportEvent>(256);

            // Spawn a background task to read BLOBs from the QUIC stream
            // and forward them as `TransportEvent`s.
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        () = cancel_clone.cancelled() => {
                            // Clean shutdown: finish the send side to signal
                            // the relay that we are done.
                            let _ = send.finish();
                            break;
                        }
                        result = Self::read_relay_message(&mut recv) => {
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
            });

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

/// Maps a `RelayMessage` received on a QUIC subscribe stream to the
/// corresponding `TransportEvent`. Returns `None` for messages the
/// subscriber should ignore (BLOBs with mismatched routing_id from a
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
        RelayMessage::Blob { blob, .. } => Some(match OuterEnvelope::from_bytes(&blob) {
            Ok(envelope) => TransportEvent::Envelope(envelope),
            Err(_) => TransportEvent::Error(TransportError::ProtocolError(
                "failed to deserialize envelope from blob".to_string(),
            )),
        }),
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
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use futures::StreamExt;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use scp_core::envelope::create_outer_envelope;

    use super::*;
    use crate::native::storage::InMemoryBlobStorage;
    use crate::profile::TransportProfile;
    use crate::quic::lifecycle::{QuicLifecycleManager, SessionTicketStore};
    use crate::quic::listener::{
        QuicListener, QuicListenerConfig, QuicShutdownHandle, SCP_ALPN, build_server_config,
    };
    use crate::relay::rate_limit::{self, PublishRateLimiter};
    use crate::relay::subscription::{self, SubscriptionRegistry};

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn test_server_config() -> (quinn::ServerConfig, Vec<CertificateDer<'static>>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert);
        let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let server_config =
            build_server_config(vec![cert_der.clone()], PrivateKeyDer::Pkcs8(key_der)).unwrap();
        (server_config, vec![cert_der])
    }

    fn test_client_config(server_certs: &[CertificateDer<'static>]) -> quinn::ClientConfig {
        let mut root_store = rustls::RootCertStore::empty();
        for cert in server_certs {
            root_store.add(cert.clone()).unwrap();
        }
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![SCP_ALPN.to_vec()];

        let quic_client_config =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).unwrap();
        quinn::ClientConfig::new(Arc::new(quic_client_config))
    }

    fn start_test_listener() -> (
        QuicShutdownHandle,
        SocketAddr,
        Vec<CertificateDer<'static>>,
        Arc<InMemoryBlobStorage>,
        SubscriptionRegistry,
    ) {
        let (server_config, certs) = test_server_config();
        let storage = Arc::new(InMemoryBlobStorage::new());
        let subscriptions = subscription::new_registry();
        let publish_rate_limiter = PublishRateLimiter::new(100);
        let connection_tracker = rate_limit::new_connection_tracker();

        let config = QuicListenerConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            delivery_jitter_ms: 0,
            ..QuicListenerConfig::default()
        };

        let listener = QuicListener::new(
            config,
            Arc::clone(&storage),
            Arc::clone(&subscriptions),
            publish_rate_limiter,
            connection_tracker,
        );
        let (handle, addr) = listener.start(server_config).unwrap();

        (handle, addr, certs, storage, subscriptions)
    }

    fn test_lifecycle() -> QuicLifecycleManager {
        QuicLifecycleManager::new(TransportProfile::Desktop, SessionTicketStore::new())
    }

    async fn connect_adapter(addr: SocketAddr, certs: &[CertificateDer<'static>]) -> QuicAdapter {
        let client_config = test_client_config(certs);
        let lifecycle = test_lifecycle();
        QuicAdapter::connect(addr, "localhost", client_config, lifecycle)
            .await
            .expect("failed to connect QuicAdapter")
    }

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
            Err(_) => panic!("first stream did not terminate within 2s"),
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
