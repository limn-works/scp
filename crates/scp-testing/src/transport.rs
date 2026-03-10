//! In-memory transport adapter for testing.
//!
//! [`InMemoryTransport`] implements [`TransportAdapter`] by wrapping an
//! [`InMemoryRelay`]. This bridges the transport trait's `OuterEnvelope`-based
//! API to the relay's raw-byte storage, using `MessagePack` serialization for
//! the round trip.
//!
//! The relay is behind `Arc<std::sync::Mutex<_>>` so multiple transports (or
//! the test harness itself) can share a single relay instance.

#![forbid(unsafe_code)]

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures::Stream;
use scp_core::envelope::OuterEnvelope;
use scp_transport::error::TransportError;
use scp_transport::traits::{
    BlobId, RoutingId, SubscriptionStream, TransportAdapter, TransportEvent,
};

use crate::relay::InMemoryRelay;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Serializes an [`OuterEnvelope`] to `MessagePack` bytes.
///
/// # Errors
///
/// Returns [`TransportError::SendFailed`] if serialization fails.
fn serialize_envelope(envelope: &OuterEnvelope) -> Result<Vec<u8>, TransportError> {
    rmp_serde::to_vec_named(envelope)
        .map_err(|e| TransportError::SendFailed(format!("envelope serialization failed: {e}")))
}

/// Deserializes an [`OuterEnvelope`] from `MessagePack` bytes.
///
/// # Errors
///
/// Returns [`TransportError::ProtocolError`] if deserialization fails.
fn deserialize_envelope(data: &[u8]) -> Result<OuterEnvelope, TransportError> {
    rmp_serde::from_slice(data)
        .map_err(|e| TransportError::ProtocolError(format!("envelope deserialization failed: {e}")))
}

/// Extracts a `[u8; 32]` routing key from the envelope's `routing_id` field.
///
/// # Errors
///
/// Returns [`TransportError::SendFailed`] if the routing ID is not exactly
/// 32 bytes.
fn routing_id_to_array(routing_id: &[u8]) -> Result<[u8; 32], TransportError> {
    <[u8; 32]>::try_from(routing_id).map_err(|_| {
        TransportError::SendFailed(format!(
            "routing_id must be 32 bytes, got {}",
            routing_id.len()
        ))
    })
}

/// Converts a [`RoutingId`] to the `[u8; 32]` expected by [`InMemoryRelay`].
const fn trait_routing_id_to_array(routing_id: &RoutingId) -> [u8; 32] {
    routing_id.0
}

// ---------------------------------------------------------------------------
// InMemoryTransport
// ---------------------------------------------------------------------------

/// In-memory [`TransportAdapter`] backed by an [`InMemoryRelay`].
///
/// Envelopes are serialized to `MessagePack` before being stored in the relay,
/// and deserialized back when queried. Subscriptions are bridged from the
/// relay's `tokio::sync::mpsc` channels into the trait's
/// [`SubscriptionStream`].
///
/// # Thread safety
///
/// The relay is behind `Arc<Mutex<_>>`. The mutex is held only for the
/// duration of each individual operation (store, subscribe, query, etc.).
/// It is never held across `await` points.
pub struct InMemoryTransport {
    /// Shared relay instance.
    relay: Arc<Mutex<InMemoryRelay>>,
    /// Clock timestamp supplier. Returns epoch seconds for the relay's
    /// `stored_at` field. Defaults to 0 if no clock is configured.
    timestamp_fn: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl InMemoryTransport {
    /// Creates a new transport backed by the given relay.
    ///
    /// Stored timestamps default to `0`. Use [`with_clock`](Self::with_clock)
    /// to provide a clock.
    #[must_use]
    pub fn new(relay: Arc<Mutex<InMemoryRelay>>) -> Self {
        Self {
            relay,
            timestamp_fn: Arc::new(|| 0),
        }
    }

    /// Creates a new transport backed by the given relay, with a clock
    /// function for timestamps.
    ///
    /// The `timestamp_fn` is called once per [`send`](TransportAdapter::send)
    /// to obtain the `stored_at` epoch-seconds value.
    #[must_use]
    pub fn with_clock(
        relay: Arc<Mutex<InMemoryRelay>>,
        timestamp_fn: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            relay,
            timestamp_fn,
        }
    }
}

// ---------------------------------------------------------------------------
// TransportAdapter implementation
// ---------------------------------------------------------------------------

impl TransportAdapter for InMemoryTransport {
    fn send(
        &self,
        envelope: &OuterEnvelope,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<BlobId, TransportError>> + Send + '_>>
    {
        // Capture everything we need before the async block to avoid
        // holding the mutex across an await point.
        let data = serialize_envelope(envelope);
        let routing_result = routing_id_to_array(&envelope.routing_id);
        let ttl = Some(u64::from(envelope.blob_ttl));
        let timestamp = (self.timestamp_fn)();
        let relay = Arc::clone(&self.relay);

        Box::pin(async move {
            let data = data?;
            let routing_id = routing_result?;

            let blob_id = {
                let mut guard = relay
                    .lock()
                    .map_err(|_| TransportError::SendFailed("relay lock poisoned".to_owned()))?;
                guard.store(routing_id, data, ttl, timestamp)
            };

            Ok(BlobId::new(blob_id))
        })
    }

    fn subscribe(
        &self,
        routing_id: &RoutingId,
        _since: Option<u64>,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<SubscriptionStream, TransportError>>
                + Send
                + '_,
        >,
    > {
        let key = trait_routing_id_to_array(routing_id);
        let relay = Arc::clone(&self.relay);

        Box::pin(async move {
            let mut guard = relay.lock().map_err(|_| {
                TransportError::SubscriptionFailed("relay lock poisoned".to_owned())
            })?;

            let (_sub_id, rx) = guard.subscribe(key);
            drop(guard);

            // Wrap the mpsc receiver as an async Stream of TransportEvent.
            let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(rx);
            let mapped: Pin<Box<dyn Stream<Item = TransportEvent> + Send>> =
                Box::pin(futures::StreamExt::map(stream, |msg| {
                    // Attempt to deserialize the relay message back into an
                    // OuterEnvelope. If that fails, emit an error event.
                    match deserialize_envelope(&msg.data) {
                        Ok(envelope) => TransportEvent::Envelope(envelope),
                        Err(e) => TransportEvent::Error(e),
                    }
                }));

            Ok(mapped)
        })
    }

    fn unsubscribe(
        &self,
        routing_id: &RoutingId,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + '_>> {
        let key = trait_routing_id_to_array(routing_id);
        let relay = Arc::clone(&self.relay);

        Box::pin(async move {
            // The TransportAdapter::unsubscribe trait operates by routing_id,
            // but InMemoryRelay::unsubscribe requires a SubscriberId. Since
            // this adapter doesn't track individual subscriber IDs (the trait
            // API doesn't expose them), we accept this as a no-op at the relay
            // level. The stream returned by subscribe() terminates when the
            // caller drops it, which causes the mpsc sender to be cleaned up
            // on the next delivery attempt.
            let _ = (relay, key);

            Ok(())
        })
    }

    fn query(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<Vec<OuterEnvelope>, TransportError>>
                + Send
                + '_,
        >,
    > {
        let key = trait_routing_id_to_array(routing_id);
        let relay = Arc::clone(&self.relay);

        Box::pin(async move {
            let blobs: Vec<_> = relay
                .lock()
                .map_err(|_| TransportError::SendFailed("relay lock poisoned".to_owned()))?
                .query(&key)
                .into_iter()
                .cloned()
                .collect();

            let mut envelopes = Vec::with_capacity(blobs.len());
            for blob in blobs {
                // Apply `since` filter if provided.
                if let Some(since_ts) = since
                    && blob.stored_at < since_ts
                {
                    continue;
                }
                envelopes.push(deserialize_envelope(&blob.data)?);
            }

            Ok(envelopes)
        })
    }

    fn delete(
        &self,
        blob_id: &BlobId,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + '_>> {
        let id = *blob_id.as_bytes();
        let relay = Arc::clone(&self.relay);

        Box::pin(async move {
            relay
                .lock()
                .map_err(|_| TransportError::SendFailed("relay lock poisoned".to_owned()))?
                .delete(&id);

            Ok(())
        })
    }
}
