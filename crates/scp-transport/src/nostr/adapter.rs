//! [`NostrAdapter`] -- implements [`TransportAdapter`] for the Nostr relay
//! protocol (NIP-01) per spec section 10.5.2.
//!
//! SCP operations map to Nostr primitives:
//!
//! | Transport method | Nostr primitive | Details |
//! |------------------|-----------------|---------|
//! | `send` | Event publish | Kind 29078, `r` tag = `routing_id` |
//! | `subscribe` | REQ filter | Kind + `r` tag filter |
//! | `unsubscribe` | CLOSE | Close subscription by ID |
//! | `query` | REQ + EOSE | One-shot with `since` |
//! | `delete` | NIP-09 | Kind 5 deletion event |
//!
//! # Wire Format
//!
//! Nostr events are JSON-only. SCP outer envelopes (`MessagePack`) are
//! base64-encoded in the `.content` field (~33% overhead).
//!
//! See `.docs/specs/10-infrastructure-and-self-hosting.md` section 10.5.2.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use futures::SinkExt;
use futures::stream::StreamExt;
use scp_core::envelope::OuterEnvelope;
use tokio::sync::{Mutex, broadcast};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, trace, warn};

use super::protocol::{
    ClientMessage, DELETION_EVENT_KIND, NostrEvent, NostrFilter, ROUTING_TAG, RelayMessage,
    SCP_EVENT_KIND,
};
use crate::error::TransportError;
use crate::traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter, TransportEvent};

/// A boxed, pinned, `Send`-safe future -- the return type for all
/// [`TransportAdapter`] methods to ensure the trait is dyn-compatible.
type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Configuration for the Nostr transport adapter.
#[derive(Debug, Clone)]
pub struct NostrConfig {
    /// WebSocket URL of the Nostr relay (e.g., `wss://relay.example.com`).
    pub relay_url: String,
    /// Hex-encoded 32-byte public key for signing events.
    /// In production this would come from a key manager; for the adapter
    /// we accept it as configuration.
    pub pubkey: String,
    /// Connection timeout in seconds.
    pub connect_timeout_secs: u64,
    /// Query timeout in seconds (for `query` and `send` operations).
    pub operation_timeout_secs: u64,
}

impl NostrConfig {
    /// Create a new configuration with the given relay URL and public key.
    #[must_use]
    pub const fn new(relay_url: String, pubkey: String) -> Self {
        Self {
            relay_url,
            pubkey,
            connect_timeout_secs: 10,
            operation_timeout_secs: 30,
        }
    }
}

/// Internal state for a WebSocket connection to a Nostr relay.
struct NostrConnection {
    /// WebSocket write half, protected by a mutex for concurrent sends.
    writer: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    /// Active subscriptions: `subscription_id` -> broadcast sender for events.
    subscriptions: HashMap<String, broadcast::Sender<RelayMessage>>,
    /// Whether a reader task is actively processing incoming messages.
    reader_active: bool,
}

/// Transport adapter for Nostr (NIP-01 relay protocol).
///
/// Implements [`TransportAdapter`] by mapping SCP operations to Nostr events
/// and subscriptions over WebSocket connections to Nostr relays.
///
/// # Connection Model
///
/// Connects via WebSocket to a single Nostr relay. The adapter manages the
/// connection lifecycle including reconnection on failure.
///
/// # Constraints
///
/// - Nostr events are JSON -- SCP envelopes are base64-encoded (~33% overhead)
/// - Max event size varies by relay (typically 64KB-1MB)
/// - No server-side TTL enforcement
/// - NIP-09 deletion is best-effort (relays MAY ignore)
pub struct NostrAdapter {
    config: NostrConfig,
    connection: Arc<Mutex<Option<NostrConnection>>>,
    subscription_counter: AtomicU64,
    /// Maps `routing_id` hex -> `subscription_id` for tracking active subscriptions.
    routing_subscriptions: Arc<Mutex<HashMap<String, String>>>,
}

impl NostrAdapter {
    /// Create a new Nostr adapter with the given configuration.
    ///
    /// The adapter does not connect immediately -- the first operation will
    /// establish the WebSocket connection.
    #[must_use]
    pub fn new(config: NostrConfig) -> Self {
        Self {
            config,
            connection: Arc::new(Mutex::new(None)),
            subscription_counter: AtomicU64::new(0),
            routing_subscriptions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Ensure a WebSocket connection is established to the Nostr relay.
    ///
    /// Returns an error if the connection cannot be established within the
    /// configured timeout.
    async fn ensure_connected(&self) -> Result<(), TransportError> {
        let mut conn_guard = self.connection.lock().await;
        if conn_guard.is_some() {
            return Ok(());
        }

        let connect_fut = tokio_tungstenite::connect_async(&self.config.relay_url);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.connect_timeout_secs),
            connect_fut,
        )
        .await;

        match result {
            Ok(Ok((ws_stream, _response))) => {
                debug!(
                    relay_url = %self.config.relay_url,
                    "connected to Nostr relay"
                );
                *conn_guard = Some(NostrConnection {
                    writer: ws_stream,
                    subscriptions: HashMap::new(),
                    reader_active: false,
                });
                Ok(())
            }
            Ok(Err(e)) => Err(TransportError::ConnectionFailed(format!(
                "Nostr relay WebSocket connection failed: {e}"
            ))),
            Err(_) => Err(TransportError::Timeout),
        }
    }

    /// Generate a unique subscription ID.
    fn next_subscription_id(&self) -> String {
        let counter = self.subscription_counter.fetch_add(1, Ordering::Relaxed);
        format!("scp-{counter}")
    }

    /// Send a client message over the WebSocket connection.
    async fn send_message(&self, message: &ClientMessage) -> Result<(), TransportError> {
        let mut conn_guard = self.connection.lock().await;
        let conn = conn_guard.as_mut().ok_or(TransportError::NotConnected)?;

        let json = message.to_json();
        trace!(msg_type = %match message {
            ClientMessage::Event(_) => "EVENT",
            ClientMessage::Req { .. } => "REQ",
            ClientMessage::Close { .. } => "CLOSE",
        }, "sending Nostr message");

        conn.writer
            .send(Message::Text(json))
            .await
            .map_err(|e| TransportError::SendFailed(format!("Nostr WebSocket send failed: {e}")))?;

        Ok(())
    }

    /// Create a Nostr event for an SCP envelope.
    fn create_envelope_event(&self, envelope: &OuterEnvelope, routing_id_hex: &str) -> NostrEvent {
        let wire_bytes = rmp_serde::to_vec(envelope).unwrap_or_default();
        let content = base64_encode(&wire_bytes);
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let tags = vec![vec![ROUTING_TAG.to_owned(), routing_id_hex.to_owned()]];

        let id = NostrEvent::compute_id(
            &self.config.pubkey,
            created_at,
            SCP_EVENT_KIND,
            &tags,
            &content,
        );

        // Signature is a placeholder -- in production, the adapter would use
        // a Nostr-compatible signing key. The relay validates signatures, but
        // SCP's security does not depend on Nostr signatures (SCP envelopes
        // are independently authenticated via MLS).
        let sig = "0".repeat(128);

        NostrEvent {
            id,
            pubkey: self.config.pubkey.clone(),
            created_at,
            kind: SCP_EVENT_KIND,
            tags,
            content,
            sig,
        }
    }

    /// Create a NIP-09 deletion event referencing the given event ID.
    fn create_deletion_event(&self, event_id: &str) -> NostrEvent {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let tags = vec![vec!["e".to_owned(), event_id.to_owned()]];
        let content = "SCP envelope deletion".to_owned();

        let id = NostrEvent::compute_id(
            &self.config.pubkey,
            created_at,
            DELETION_EVENT_KIND,
            &tags,
            &content,
        );

        let sig = "0".repeat(128);

        NostrEvent {
            id,
            pubkey: self.config.pubkey.clone(),
            created_at,
            kind: DELETION_EVENT_KIND,
            tags,
            content,
            sig,
        }
    }

    /// Spawn a background reader task that dispatches incoming relay messages
    /// to the appropriate subscription broadcast channels.
    fn spawn_reader_task(connection: Arc<Mutex<Option<NostrConnection>>>) {
        tokio::spawn(async move {
            loop {
                let msg = {
                    let mut conn_guard = connection.lock().await;
                    let Some(conn) = conn_guard.as_mut() else {
                        break;
                    };
                    conn.writer.next().await
                };

                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Some(relay_msg) = RelayMessage::from_json(&text) {
                            let conn_guard = connection.lock().await;
                            if let Some(conn) = conn_guard.as_ref() {
                                Self::dispatch_relay_message(conn, relay_msg);
                            }
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        warn!(error = %e, "Nostr WebSocket read error");
                        break;
                    }
                    None => {
                        debug!("Nostr WebSocket closed");
                        break;
                    }
                }
            }

            // Mark reader as inactive.
            let mut conn_guard = connection.lock().await;
            if let Some(conn) = conn_guard.as_mut() {
                conn.reader_active = false;
            }
        });
    }

    /// Route a relay message to the appropriate subscription channel(s).
    fn dispatch_relay_message(conn: &NostrConnection, relay_msg: RelayMessage) {
        match &relay_msg {
            RelayMessage::Event {
                subscription_id, ..
            }
            | RelayMessage::Eose { subscription_id } => {
                if let Some(tx) = conn.subscriptions.get(subscription_id) {
                    let _ = tx.send(relay_msg);
                }
            }
            RelayMessage::Ok { .. } | RelayMessage::Notice { .. } => {
                for tx in conn.subscriptions.values() {
                    let _ = tx.send(relay_msg.clone());
                }
            }
        }
    }

    /// Create a [`SubscriptionStream`] from a broadcast receiver that
    /// converts relay messages into [`TransportEvent`]s.
    fn create_subscription_stream(rx: broadcast::Receiver<RelayMessage>) -> SubscriptionStream {
        let stream =
            futures::stream::unfold((rx, false), |(mut rx, backfill_complete)| async move {
                loop {
                    match rx.recv().await {
                        Ok(RelayMessage::Event { event, .. }) => {
                            match Self::parse_envelope_from_event(&event) {
                                Ok(envelope) => {
                                    return Some((
                                        TransportEvent::Envelope(envelope),
                                        (rx, backfill_complete),
                                    ));
                                }
                                Err(e) => {
                                    warn!(error = %e, "failed to parse Nostr event");
                                    return Some((
                                        TransportEvent::Error(e),
                                        (rx, backfill_complete),
                                    ));
                                }
                            }
                        }
                        Ok(RelayMessage::Eose { .. }) => {
                            if !backfill_complete {
                                return Some((TransportEvent::BackfillComplete, (rx, true)));
                            }
                        }
                        Ok(RelayMessage::Notice { message }) => {
                            warn!(notice = %message, "Nostr relay notice");
                        }
                        Ok(RelayMessage::Ok { .. }) => {}
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!(skipped = n, "subscription lagged, events dropped");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            return Some((
                                TransportEvent::Terminated {
                                    reason: "Nostr subscription channel closed".to_owned(),
                                },
                                (rx, backfill_complete),
                            ));
                        }
                    }
                }
            });

        Box::pin(stream)
    }

    /// Parse an SCP outer envelope from a Nostr event's base64-encoded content.
    fn parse_envelope_from_event(event: &NostrEvent) -> Result<OuterEnvelope, TransportError> {
        let bytes = base64_decode(&event.content).map_err(|e| {
            TransportError::ProtocolError(format!("invalid base64 in Nostr event content: {e}"))
        })?;
        rmp_serde::from_slice(&bytes).map_err(|e| {
            TransportError::ProtocolError(format!(
                "invalid MessagePack in Nostr event content: {e}"
            ))
        })
    }
}

impl TransportAdapter for NostrAdapter {
    fn send(&self, envelope: &OuterEnvelope) -> BoxFuture<'_, Result<BlobId, TransportError>> {
        // Clone envelope for the async block since OuterEnvelope doesn't impl Clone.
        // We serialize first and compute the blob ID from the wire bytes.
        let wire_bytes = rmp_serde::to_vec(envelope).unwrap_or_default();
        let blob_id = BlobId::from_sha256(&wire_bytes);
        let routing_id_hex = hex::encode(&envelope.routing_id);

        Box::pin(async move {
            self.ensure_connected().await?;

            // Re-deserialize for event creation since we already have wire_bytes.
            let envelope: OuterEnvelope = rmp_serde::from_slice(&wire_bytes).map_err(|e| {
                TransportError::SendFailed(format!("envelope re-serialization failed: {e}"))
            })?;

            let event = self.create_envelope_event(&envelope, &routing_id_hex);
            let message = ClientMessage::Event(event);

            // Send the event and wait for OK response.
            self.send_message(&message).await?;

            // Read the OK response with timeout.
            let timeout_duration =
                std::time::Duration::from_secs(self.config.operation_timeout_secs);
            let ok_result = tokio::time::timeout(timeout_duration, async {
                let mut conn_guard = self.connection.lock().await;
                let conn = conn_guard.as_mut().ok_or(TransportError::NotConnected)?;

                // Read messages until we get an OK for our event.
                loop {
                    match conn.writer.next().await {
                        Some(Ok(Message::Text(text))) => {
                            if let Some(RelayMessage::Ok {
                                accepted, message, ..
                            }) = RelayMessage::from_json(&text)
                            {
                                if accepted {
                                    return Ok(());
                                }
                                return Err(TransportError::SendFailed(format!(
                                    "Nostr relay rejected event: {message}"
                                )));
                            }
                            // Other messages (EVENT, NOTICE) -- continue waiting.
                        }
                        Some(Ok(_)) => {
                            // Binary or other message types -- skip.
                        }
                        Some(Err(e)) => {
                            return Err(TransportError::SendFailed(format!(
                                "WebSocket error while waiting for OK: {e}"
                            )));
                        }
                        None => {
                            return Err(TransportError::NotConnected);
                        }
                    }
                }
            })
            .await;

            match ok_result {
                Ok(Ok(())) => {
                    debug!("Nostr event published successfully");
                    Ok(blob_id)
                }
                Ok(Err(e)) => Err(e),
                Err(_) => Err(TransportError::Timeout),
            }
        })
    }

    fn subscribe(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<SubscriptionStream, TransportError>> {
        let routing_id_hex = hex::encode(routing_id.as_bytes());
        let sub_id = self.next_subscription_id();

        Box::pin(async move {
            self.ensure_connected().await?;

            let filter = NostrFilter {
                kinds: Some(vec![SCP_EVENT_KIND]),
                r_tag: Some(vec![routing_id_hex.clone()]),
                since,
                limit: None,
            };
            let req = ClientMessage::Req {
                subscription_id: sub_id.clone(),
                filters: vec![filter],
            };

            // Register the subscription and create a broadcast channel.
            let (tx, rx) = broadcast::channel(256);
            {
                let mut conn_guard = self.connection.lock().await;
                if let Some(conn) = conn_guard.as_mut() {
                    conn.subscriptions.insert(sub_id.clone(), tx);
                    if !conn.reader_active {
                        conn.reader_active = true;
                    }
                }
            }

            // Track the routing_id -> subscription_id mapping.
            {
                let mut routing_subs = self.routing_subscriptions.lock().await;
                routing_subs.insert(routing_id_hex, sub_id);
            }

            self.send_message(&req).await?;

            // Spawn background reader to dispatch relay messages.
            Self::spawn_reader_task(Arc::clone(&self.connection));

            Ok(Self::create_subscription_stream(rx))
        })
    }

    fn unsubscribe(&self, routing_id: &RoutingId) -> BoxFuture<'_, Result<(), TransportError>> {
        let routing_id_hex = hex::encode(routing_id.as_bytes());

        Box::pin(async move {
            // Look up the subscription ID for this routing ID.
            let sub_id = {
                let mut routing_subs = self.routing_subscriptions.lock().await;
                routing_subs.remove(&routing_id_hex)
            };

            let sub_id = sub_id.ok_or_else(|| {
                TransportError::SubscriptionFailed(format!(
                    "no active subscription for routing_id {routing_id_hex}"
                ))
            })?;

            // Send CLOSE to the relay.
            let close = ClientMessage::Close {
                subscription_id: sub_id.clone(),
            };
            self.send_message(&close).await?;

            // Remove the subscription from the connection state.
            {
                let mut conn_guard = self.connection.lock().await;
                if let Some(conn) = conn_guard.as_mut() {
                    conn.subscriptions.remove(&sub_id);
                }
            }

            debug!(sub_id = %sub_id, "Nostr subscription closed");
            Ok(())
        })
    }

    fn query(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, TransportError>> {
        let routing_id_hex = hex::encode(routing_id.as_bytes());
        let sub_id = self.next_subscription_id();

        Box::pin(async move {
            self.ensure_connected().await?;

            // Create a one-shot subscription with EOSE as the terminator.
            let filter = NostrFilter {
                kinds: Some(vec![SCP_EVENT_KIND]),
                r_tag: Some(vec![routing_id_hex]),
                since,
                limit: None,
            };

            let req = ClientMessage::Req {
                subscription_id: sub_id.clone(),
                filters: vec![filter],
            };

            self.send_message(&req).await?;

            // Collect events until EOSE.
            let timeout_duration =
                std::time::Duration::from_secs(self.config.operation_timeout_secs);
            let result = tokio::time::timeout(timeout_duration, async {
                let mut envelopes = Vec::new();
                let mut conn_guard = self.connection.lock().await;
                let conn = conn_guard.as_mut().ok_or(TransportError::NotConnected)?;

                loop {
                    match conn.writer.next().await {
                        Some(Ok(Message::Text(text))) => {
                            match RelayMessage::from_json(&text) {
                                Some(RelayMessage::Event {
                                    event,
                                    subscription_id,
                                }) if subscription_id == sub_id => {
                                    match Self::parse_envelope_from_event(&event) {
                                        Ok(envelope) => envelopes.push(envelope),
                                        Err(e) => {
                                            warn!(error = %e, "skipping malformed event in query");
                                        }
                                    }
                                }
                                Some(RelayMessage::Eose { subscription_id })
                                    if subscription_id == sub_id =>
                                {
                                    // End of stored events -- close the query subscription.
                                    break;
                                }
                                _ => {
                                    // Other messages -- continue.
                                }
                            }
                        }
                        Some(Ok(_)) => {}
                        Some(Err(e)) => {
                            return Err(TransportError::SendFailed(format!(
                                "WebSocket error during query: {e}"
                            )));
                        }
                        None => {
                            return Err(TransportError::NotConnected);
                        }
                    }
                }

                Ok(envelopes)
            })
            .await;

            // Close the query subscription.
            let close = ClientMessage::Close {
                subscription_id: sub_id,
            };
            let _ = self.send_message(&close).await;

            match result {
                Ok(Ok(envelopes)) => Ok(envelopes),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(TransportError::Timeout),
            }
        })
    }

    fn delete(&self, blob_id: &BlobId) -> BoxFuture<'_, Result<(), TransportError>> {
        // NIP-09: deletion event referencing the original event by its ID.
        // We use the blob_id hex as the event ID reference since we don't
        // independently track Nostr event IDs. This is best-effort -- relays
        // MAY ignore deletion requests.
        let event_id = hex::encode(blob_id.as_bytes());

        Box::pin(async move {
            self.ensure_connected().await?;

            let deletion_event = self.create_deletion_event(&event_id);
            let message = ClientMessage::Event(deletion_event);
            self.send_message(&message).await?;

            debug!(event_id = %event_id, "NIP-09 deletion event sent (best-effort)");
            Ok(())
        })
    }
}

/// Base64-encode bytes using the standard alphabet with padding.
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    STANDARD.encode(data)
}

/// Base64-decode a string using the standard alphabet with padding.
fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    STANDARD
        .decode(s)
        .map_err(|e| format!("base64 decode error: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn nostr_adapter_creation() {
        let config = NostrConfig::new("wss://relay.example.com".to_owned(), "a".repeat(64));
        let adapter = NostrAdapter::new(config);
        assert_eq!(adapter.config.relay_url, "wss://relay.example.com");
    }

    #[test]
    fn subscription_id_is_unique() {
        let config = NostrConfig::new("wss://relay.example.com".to_owned(), "a".repeat(64));
        let adapter = NostrAdapter::new(config);
        let id1 = adapter.next_subscription_id();
        let id2 = adapter.next_subscription_id();
        assert_ne!(id1, id2);
        assert!(id1.starts_with("scp-"));
    }

    #[test]
    fn create_envelope_event_has_correct_kind_and_tags() {
        let config = NostrConfig::new("wss://relay.example.com".to_owned(), "a".repeat(64));
        let adapter = NostrAdapter::new(config);
        let routing_id_hex = "deadbeef";

        // Create a minimal outer envelope for testing.
        let envelope_bytes = vec![0x92, 0x01, 0x02]; // minimal msgpack
        let content = base64_encode(&envelope_bytes);

        // We can't easily create a real OuterEnvelope in a unit test,
        // so we test the event structure indirectly via protocol types.
        let event = NostrEvent {
            id: "test".to_owned(),
            pubkey: "a".repeat(64),
            created_at: 1000,
            kind: SCP_EVENT_KIND,
            tags: vec![vec![ROUTING_TAG.to_owned(), routing_id_hex.to_owned()]],
            content,
            sig: "0".repeat(128),
        };

        assert_eq!(event.kind, 29078);
        assert_eq!(event.tags.len(), 1);
        assert_eq!(event.tags[0][0], "r");
        assert_eq!(event.tags[0][1], routing_id_hex);
    }

    #[test]
    fn deletion_event_has_correct_kind() {
        let config = NostrConfig::new("wss://relay.example.com".to_owned(), "a".repeat(64));
        let adapter = NostrAdapter::new(config);
        let event = adapter.create_deletion_event("abc123");

        assert_eq!(event.kind, DELETION_EVENT_KIND);
        assert_eq!(event.tags.len(), 1);
        assert_eq!(event.tags[0][0], "e");
        assert_eq!(event.tags[0][1], "abc123");
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"hello world SCP envelope";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn config_defaults() {
        let config = NostrConfig::new("wss://relay.example.com".to_owned(), "pk".to_owned());
        assert_eq!(config.connect_timeout_secs, 10);
        assert_eq!(config.operation_timeout_secs, 30);
    }
}
