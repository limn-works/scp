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
//! # Schnorr Signing
//!
//! Events are signed with BIP-340 Schnorr signatures using the secp256k1
//! curve. The signing key is injected at construction time. The public key
//! is derived from the signing key (x-only, per BIP-340).
//!
//! See `.docs/specs/10-infrastructure-and-self-hosting.md` section 10.5.2.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use futures::SinkExt;
use futures::stream::StreamExt;
use k256::schnorr::signature::Signer;
use k256::schnorr::{SigningKey, VerifyingKey};
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
    /// 32-byte secret key for BIP-340 Schnorr signing.
    /// The public key is derived from this automatically.
    pub signing_key: [u8; 32],
    /// Connection timeout in seconds.
    pub connect_timeout_secs: u64,
    /// Query timeout in seconds (for `query` and `send` operations).
    pub operation_timeout_secs: u64,
}

impl NostrConfig {
    /// Create a new configuration with the given relay URL and signing key.
    #[must_use]
    pub const fn new(relay_url: String, signing_key: [u8; 32]) -> Self {
        Self {
            relay_url,
            signing_key,
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
/// # Signing
///
/// Events are signed with BIP-340 Schnorr signatures. The signing key is
/// provided at construction time; the x-only public key is derived from it.
///
/// # Constraints
///
/// - Nostr events are JSON -- SCP envelopes are base64-encoded (~33% overhead)
/// - Max event size varies by relay (typically 64KB-1MB)
/// - No server-side TTL enforcement
/// - NIP-09 deletion is best-effort (relays MAY ignore)
pub struct NostrAdapter {
    config: NostrConfig,
    /// BIP-340 Schnorr signing key for event signatures.
    signing_key: SigningKey,
    /// Hex-encoded x-only public key (BIP-340 format, 32 bytes = 64 hex chars).
    pubkey_hex: String,
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
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ProtocolError`] if the signing key bytes
    /// are not a valid secp256k1 secret key.
    pub fn new(config: NostrConfig) -> Result<Self, TransportError> {
        let signing_key = SigningKey::from_bytes(&config.signing_key).map_err(|e| {
            TransportError::ProtocolError(format!("invalid Nostr signing key: {e}"))
        })?;
        let verifying_key: &VerifyingKey = signing_key.verifying_key();
        let pubkey_hex = hex::encode(verifying_key.to_bytes());

        Ok(Self {
            config,
            signing_key,
            pubkey_hex,
            connection: Arc::new(Mutex::new(None)),
            subscription_counter: AtomicU64::new(0),
            routing_subscriptions: Arc::new(Mutex::new(HashMap::new())),
        })
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

        let json = message.to_json()?;
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

    /// Returns the hex-encoded x-only public key (BIP-340, 32 bytes = 64 hex chars).
    #[must_use]
    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    /// Returns a reference to the BIP-340 verifying key for signature verification.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign an event with BIP-340 Schnorr and return the hex-encoded signature.
    pub fn sign_event(&self, event: &NostrEvent) -> Result<String, TransportError> {
        let id_bytes = event.id_bytes()?;
        let signature: k256::schnorr::Signature = self.signing_key.sign(&id_bytes);
        Ok(hex::encode(signature.to_bytes()))
    }

    /// Create a Nostr event for an SCP envelope.
    fn create_envelope_event(
        &self,
        envelope: &OuterEnvelope,
        routing_id_hex: &str,
    ) -> Result<NostrEvent, TransportError> {
        let wire_bytes = rmp_serde::to_vec_named(envelope).map_err(|e| {
            TransportError::SendFailed(format!("envelope serialization failed: {e}"))
        })?;
        let content = base64_encode(&wire_bytes);
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                TransportError::ProtocolError(format!("system time before UNIX epoch: {e}"))
            })?
            .as_secs();
        let tags = vec![vec![ROUTING_TAG.to_owned(), routing_id_hex.to_owned()]];

        let id = NostrEvent::compute_id(
            &self.pubkey_hex,
            created_at,
            SCP_EVENT_KIND,
            &tags,
            &content,
        )?;

        let mut event = NostrEvent {
            id,
            pubkey: self.pubkey_hex.clone(),
            created_at,
            kind: SCP_EVENT_KIND,
            tags,
            content,
            sig: String::new(),
        };

        event.sig = self.sign_event(&event)?;

        Ok(event)
    }

    /// Create a NIP-09 deletion event referencing the given event ID.
    pub fn create_deletion_event(&self, event_id: &str) -> Result<NostrEvent, TransportError> {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                TransportError::ProtocolError(format!("system time before UNIX epoch: {e}"))
            })?
            .as_secs();
        let tags = vec![vec!["e".to_owned(), event_id.to_owned()]];
        let content = "SCP envelope deletion".to_owned();

        let id = NostrEvent::compute_id(
            &self.pubkey_hex,
            created_at,
            DELETION_EVENT_KIND,
            &tags,
            &content,
        )?;

        let mut event = NostrEvent {
            id,
            pubkey: self.pubkey_hex.clone(),
            created_at,
            kind: DELETION_EVENT_KIND,
            tags,
            content,
            sig: String::new(),
        };

        event.sig = self.sign_event(&event)?;

        Ok(event)
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
        let wire_result = rmp_serde::to_vec_named(envelope)
            .map_err(|e| TransportError::SendFailed(format!("envelope serialization failed: {e}")));
        let routing_id_hex = hex::encode(&envelope.routing_id);

        Box::pin(async move {
            let wire_bytes = wire_result?;
            let blob_id = BlobId::from_sha256(&wire_bytes);

            self.ensure_connected().await?;

            // Re-deserialize for event creation since we already have wire_bytes.
            let envelope: OuterEnvelope = rmp_serde::from_slice(&wire_bytes).map_err(|e| {
                TransportError::SendFailed(format!("envelope re-serialization failed: {e}"))
            })?;

            let event = self.create_envelope_event(&envelope, &routing_id_hex)?;
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

            let deletion_event = self.create_deletion_event(&event_id)?;
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

    /// Generate a valid test signing key.
    fn test_signing_key() -> [u8; 32] {
        // A known-valid secp256k1 secret key (non-zero, less than curve order).
        let mut key = [0u8; 32];
        key[31] = 1; // smallest valid key
        key
    }

    #[test]
    fn nostr_adapter_creation() {
        let config = NostrConfig::new("wss://relay.example.com".to_owned(), test_signing_key());
        let adapter = NostrAdapter::new(config).unwrap();
        assert_eq!(adapter.config.relay_url, "wss://relay.example.com");
        // Public key should be 64 hex chars (32 bytes x-only).
        assert_eq!(adapter.pubkey_hex.len(), 64);
    }

    #[test]
    fn nostr_adapter_invalid_key_rejected() {
        let config = NostrConfig::new("wss://relay.example.com".to_owned(), [0u8; 32]);
        let result = NostrAdapter::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn subscription_id_is_unique() {
        let config = NostrConfig::new("wss://relay.example.com".to_owned(), test_signing_key());
        let adapter = NostrAdapter::new(config).unwrap();
        let id1 = adapter.next_subscription_id();
        let id2 = adapter.next_subscription_id();
        assert_ne!(id1, id2);
        assert!(id1.starts_with("scp-"));
    }

    #[test]
    fn schnorr_signature_is_valid() {
        let config = NostrConfig::new("wss://relay.example.com".to_owned(), test_signing_key());
        let adapter = NostrAdapter::new(config).unwrap();

        // Create a test event and verify it gets a real signature.
        let tags = vec![vec![ROUTING_TAG.to_owned(), "deadbeef".to_owned()]];
        let content = "test content";
        let id = NostrEvent::compute_id(&adapter.pubkey_hex, 1000, SCP_EVENT_KIND, &tags, content)
            .unwrap();

        let mut event = NostrEvent {
            id,
            pubkey: adapter.pubkey_hex.clone(),
            created_at: 1000,
            kind: SCP_EVENT_KIND,
            tags,
            content: content.to_owned(),
            sig: String::new(),
        };

        event.sig = adapter.sign_event(&event).unwrap();

        // Signature should be 128 hex chars (64 bytes).
        assert_eq!(event.sig.len(), 128);
        // Signature should NOT be all zeros (the old placeholder).
        assert_ne!(event.sig, "0".repeat(128));

        // Verify the signature with the verifying key.
        use k256::schnorr::signature::Verifier;
        let sig_bytes = hex::decode(&event.sig).unwrap();
        let signature = k256::schnorr::Signature::try_from(sig_bytes.as_slice()).unwrap();
        let id_bytes = event.id_bytes().unwrap();
        let verifying_key = adapter.signing_key.verifying_key();
        verifying_key.verify(&id_bytes, &signature).unwrap();
    }

    #[test]
    fn deletion_event_has_correct_kind() {
        let config = NostrConfig::new("wss://relay.example.com".to_owned(), test_signing_key());
        let adapter = NostrAdapter::new(config).unwrap();
        let event = adapter
            .create_deletion_event(
                "abc123def456abc123def456abc123def456abc123def456abc123def456abcd1234",
            )
            .unwrap();

        assert_eq!(event.kind, DELETION_EVENT_KIND);
        assert_eq!(event.tags.len(), 1);
        assert_eq!(event.tags[0][0], "e");
        // Signature should be real, not placeholder.
        assert_eq!(event.sig.len(), 128);
        assert_ne!(event.sig, "0".repeat(128));
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
        let config = NostrConfig::new("wss://relay.example.com".to_owned(), test_signing_key());
        assert_eq!(config.connect_timeout_secs, 10);
        assert_eq!(config.operation_timeout_secs, 30);
    }
}
