//! [`NativeRelayAdapter`] -- implements [`TransportAdapter`] for the SCP native
//! relay.
//!
//! This adapter translates between the SCP transport API ([`TransportAdapter`])
//! and the native relay protocol ([`ClientMessage`] / [`RelayMessage`]). It
//! wraps a [`NativeRelayClient`] to handle connection lifecycle, keepalive,
//! reconnection, and deduplication.
//!
//! # Mapping
//!
//! | Transport method | Relay operation |
//! |------------------|----------------|
//! | `send` | `PUBLISH` |
//! | `subscribe` | `SUBSCRIBE` + stream |
//! | `unsubscribe` | `UNSUBSCRIBE` |
//! | `query` | `QUERY` |
//! | `delete` | `DELETE` |
//!
//! See ADR-004 in `.docs/adrs/phase-1.md` for the full specification.
//!
//! [`NativeRelayClient`]: super::client::NativeRelayClient

use std::pin::Pin;

use futures::Stream;
use scp_core::envelope::OuterEnvelope;

use super::client::{NativeRelayClient, SubscriptionMessage};
use super::protocol::{ClientMessage, RelayMessage};
use crate::error::TransportError;
use crate::traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter, TransportEvent};

/// A boxed, pinned, `Send`-safe future -- the return type for all
/// [`TransportAdapter`] methods to ensure the trait is dyn-compatible.
type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Transport adapter for the SCP native relay.
///
/// Implements [`TransportAdapter`] by translating each transport operation
/// into the corresponding native relay protocol operation via a
/// [`NativeRelayClient`].
///
/// # Construction
///
/// Use [`NativeRelayAdapter::connect`] to create an adapter connected to a
/// relay at the given URL.
///
/// # Examples
///
/// ```rust,ignore
/// use scp_transport::native::adapter::NativeRelayAdapter;
///
/// let adapter = NativeRelayAdapter::connect("ws://127.0.0.1:9000/scp/v1").await?;
/// ```
pub struct NativeRelayAdapter {
    /// The underlying WebSocket client.
    client: NativeRelayClient,
}

impl NativeRelayAdapter {
    /// Creates a new adapter connected to the given relay URL.
    ///
    /// The URL should be of the form `ws://host:port/scp/v1` or
    /// `wss://host:port/scp/v1`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ConnectionFailed`] if the initial connection
    /// cannot be established.
    pub async fn connect(url: &str) -> Result<Self, TransportError> {
        let client = NativeRelayClient::connect(url).await?;
        Ok(Self { client })
    }
}

impl TransportAdapter for NativeRelayAdapter {
    /// Sends an outer envelope via PUBLISH.
    ///
    /// Extracts `routing_id`, `recipient_hint`, and `blob_ttl` from the
    /// [`OuterEnvelope`], serializes the entire envelope as the blob payload,
    /// and sends a PUBLISH command to the relay.
    ///
    /// Returns the [`BlobId`] (SHA-256 hash of the blob) assigned by the
    /// relay.
    fn send(&self, envelope: &OuterEnvelope) -> BoxFuture<'_, Result<BlobId, TransportError>> {
        // Extract all data from the envelope reference before the async block
        // to avoid lifetime issues with the borrowed `envelope`.
        let blob_result = envelope.to_bytes();
        let routing_id_vec = envelope.routing_id.clone();
        let recipient_hint_vec = envelope.recipient_hint.clone();
        let blob_ttl = envelope.blob_ttl;

        Box::pin(async move {
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

            let response = self.client.send_request(msg).await?;

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

    /// Subscribes to a routing ID via SUBSCRIBE.
    ///
    /// Returns a [`SubscriptionStream`] that yields [`TransportEvent`]s:
    /// - `TransportEvent::Envelope` for BLOB messages
    /// - `TransportEvent::BackfillComplete` for `backfill_complete` EVENTs
    /// - `TransportEvent::Reconnected` on reconnection
    /// - `TransportEvent::Terminated` on relay shutdown
    fn subscribe(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<SubscriptionStream, TransportError>> {
        let routing_id_bytes = *routing_id.as_bytes();
        Box::pin(async move {
            let rx = self.client.subscribe(&routing_id_bytes, since).await?;

            let stream = RelayMessageStream { rx };
            Ok(Box::pin(stream) as SubscriptionStream)
        })
    }

    /// Unsubscribes from a routing ID via UNSUBSCRIBE.
    fn unsubscribe(&self, routing_id: &RoutingId) -> BoxFuture<'_, Result<(), TransportError>> {
        let routing_id_bytes = *routing_id.as_bytes();
        Box::pin(async move { self.client.unsubscribe(&routing_id_bytes).await })
    }

    /// Queries stored envelopes for a routing ID via QUERY.
    ///
    /// Sends a QUERY command and collects all BLOB responses until a
    /// `query_complete` EVENT is received. Returns the collected envelopes.
    fn query(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, TransportError>> {
        let routing_id_bytes = *routing_id.as_bytes();
        Box::pin(async move { self.client.query(&routing_id_bytes, since).await })
    }

    /// Requests deletion of a blob via DELETE.
    fn delete(&self, blob_id: &BlobId) -> BoxFuture<'_, Result<(), TransportError>> {
        let blob_id_bytes = *blob_id.as_bytes();
        Box::pin(async move {
            let msg = ClientMessage::Delete {
                ref_id: None,
                blob_id: blob_id_bytes,
            };

            let response = self.client.send_request(msg).await?;

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

/// Stream adapter that converts [`SubscriptionMessage`]s from a channel into
/// [`TransportEvent`]s.
struct RelayMessageStream {
    rx: tokio::sync::mpsc::Receiver<SubscriptionMessage>,
}

impl Stream for RelayMessageStream {
    type Item = TransportEvent;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(sub_msg)) => {
                subscription_message_to_event(sub_msg).map_or_else(
                    || {
                        // Skip messages that don't map to events (e.g., PONG).
                        cx.waker().wake_by_ref();
                        std::task::Poll::Pending
                    },
                    |ev| std::task::Poll::Ready(Some(ev)),
                )
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Converts a [`SubscriptionMessage`] into a [`TransportEvent`], if
/// applicable.
///
/// Returns `None` for messages that don't map to transport events (e.g.,
/// PONG, OK responses).
fn subscription_message_to_event(msg: SubscriptionMessage) -> Option<TransportEvent> {
    match msg {
        SubscriptionMessage::Relay(relay_msg) => relay_message_to_event(relay_msg),
        SubscriptionMessage::Reconnected => Some(TransportEvent::Reconnected),
    }
}

/// Converts a [`RelayMessage`] into a [`TransportEvent`], if applicable.
///
/// Returns `None` for messages that don't map to transport events (e.g.,
/// PONG, OK responses).
fn relay_message_to_event(msg: RelayMessage) -> Option<TransportEvent> {
    match msg {
        RelayMessage::Blob { blob, .. } => match OuterEnvelope::from_bytes(&blob) {
            Ok(envelope) => Some(TransportEvent::Envelope(envelope)),
            Err(e) => Some(TransportEvent::Error(TransportError::ProtocolError(
                format!("failed to deserialize envelope from blob: {e}"),
            ))),
        },
        RelayMessage::Event { event_type, .. } => match event_type.as_str() {
            "backfill_complete" => Some(TransportEvent::BackfillComplete),
            _ => None,
        },
        RelayMessage::Err { code, msg, .. } => {
            if code == super::error::code::SHUTTING_DOWN {
                Some(TransportEvent::Terminated {
                    reason: format!("relay shutting down: {msg}"),
                })
            } else {
                Some(TransportEvent::Error(TransportError::ProtocolError(
                    format!("relay error {code}: {msg}"),
                )))
            }
        }
        // OK and PONG don't map to transport events.
        RelayMessage::Ok { .. } | RelayMessage::Pong { .. } => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::native::error::code;

    #[test]
    fn relay_blob_to_envelope_event() {
        let routing_id = [0xAA; 32];
        let blob_data = {
            let env = scp_core::envelope::create_outer_envelope(
                &routing_id,
                None,
                3600,
                vec![0x01, 0x02, 0x03],
            )
            .unwrap();
            env.to_bytes().unwrap()
        };
        let blob_id = {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(&blob_data);
            let mut out = [0u8; 32];
            out.copy_from_slice(&hash);
            out
        };

        let msg = RelayMessage::Blob {
            routing_id,
            blob_id,
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: blob_data,
        };

        let event = relay_message_to_event(msg);
        assert!(matches!(event, Some(TransportEvent::Envelope(_))));
    }

    #[test]
    fn relay_backfill_complete_to_event() {
        let msg = RelayMessage::Event {
            ref_id: None,
            event_type: "backfill_complete".to_string(),
        };

        let event = relay_message_to_event(msg);
        assert!(matches!(event, Some(TransportEvent::BackfillComplete)));
    }

    #[test]
    fn relay_query_complete_returns_none() {
        let msg = RelayMessage::Event {
            ref_id: None,
            event_type: "query_complete".to_string(),
        };

        let event = relay_message_to_event(msg);
        assert!(event.is_none());
    }

    #[test]
    fn relay_shutting_down_to_terminated() {
        let msg = RelayMessage::Err {
            ref_id: None,
            code: code::SHUTTING_DOWN,
            msg: "going down".to_string(),
        };

        let event = relay_message_to_event(msg);
        assert!(matches!(event, Some(TransportEvent::Terminated { .. })));
    }

    #[test]
    fn relay_client_error_to_error_event() {
        let msg = RelayMessage::Err {
            ref_id: None,
            code: code::INVALID_MESSAGE,
            msg: "bad message".to_string(),
        };

        let event = relay_message_to_event(msg);
        assert!(matches!(event, Some(TransportEvent::Error(_))));
    }

    #[test]
    fn relay_ok_returns_none() {
        let msg = RelayMessage::Ok {
            ref_id: None,
            blob_id: None,
        };

        let event = relay_message_to_event(msg);
        assert!(event.is_none());
    }

    #[test]
    fn relay_pong_returns_none() {
        let msg = RelayMessage::Pong { ts: 42 };

        let event = relay_message_to_event(msg);
        assert!(event.is_none());
    }

    #[test]
    fn relay_blob_with_invalid_data_to_error_event() {
        let msg = RelayMessage::Blob {
            routing_id: [0xAA; 32],
            blob_id: [0xBB; 32],
            recipient_hint: None,
            blob_ttl: 3600,
            stored_at: 1_700_000_000,
            blob: vec![0xFF, 0xFE, 0xFD], // Invalid envelope data.
        };

        let event = relay_message_to_event(msg);
        assert!(matches!(event, Some(TransportEvent::Error(_))));
    }

    #[test]
    fn subscription_reconnected_to_reconnected_event() {
        let msg = SubscriptionMessage::Reconnected;
        let event = subscription_message_to_event(msg);
        assert!(matches!(event, Some(TransportEvent::Reconnected)));
    }

    #[test]
    fn subscription_relay_delegates_to_relay_message_to_event() {
        let relay_msg = RelayMessage::Event {
            ref_id: None,
            event_type: "backfill_complete".to_string(),
        };
        let msg = SubscriptionMessage::Relay(relay_msg);
        let event = subscription_message_to_event(msg);
        assert!(matches!(event, Some(TransportEvent::BackfillComplete)));
    }

    #[test]
    fn subscription_relay_pong_returns_none() {
        let relay_msg = RelayMessage::Pong { ts: 42 };
        let msg = SubscriptionMessage::Relay(relay_msg);
        let event = subscription_message_to_event(msg);
        assert!(event.is_none());
    }
}
