//! Multi-adapter transport manager.
//!
//! [`TransportManager`] holds one or more [`TransportAdapter`] instances and
//! provides a unified interface for sending, subscribing, querying, and
//! deleting envelopes across all registered adapters.
//!
//! **Phase 1:** single adapter support (SCP native relay). Multi-adapter
//! routing with policy-based send and merged subscribe streams is Phase 2+.
//!
//! See ADR-005 in `.docs/adrs/phase-1.md` for the transport manager design.

use std::collections::HashSet;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Stream, StreamExt};
use scp_core::envelope::OuterEnvelope;

use crate::error::TransportError;
use crate::traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter, TransportEvent};

/// Multi-adapter transport manager.
///
/// Holds multiple [`TransportAdapter`] instances and routes operations
/// through them based on policy. In Phase 1, only a single adapter is
/// supported (the SCP native relay). Multi-adapter routing with policy-based
/// send selection and merged subscription streams is Phase 2+.
///
/// # Construction
///
/// Use [`TransportManager::new`] to create a manager with an initial adapter,
/// or [`TransportManager::builder`] to construct one incrementally.
///
/// # Examples
///
/// ```rust,ignore
/// let manager = TransportManager::new(my_adapter);
/// let blob_id = manager.send(&envelope).await?;
/// ```
pub struct TransportManager {
    /// Registered transport adapters, in insertion order.
    adapters: Vec<Box<dyn TransportAdapter>>,
}

impl TransportManager {
    /// Creates a new `TransportManager` with a single adapter.
    ///
    /// This is the Phase 1 constructor. The provided adapter is used for
    /// all operations.
    #[must_use]
    pub fn new(adapter: Box<dyn TransportAdapter>) -> Self {
        Self {
            adapters: vec![adapter],
        }
    }

    /// Creates a new `TransportManager` with no adapters.
    ///
    /// Use [`add_adapter`](TransportManager::add_adapter) to register
    /// adapters before performing any operations.
    #[must_use]
    pub fn builder() -> Self {
        Self {
            adapters: Vec::new(),
        }
    }

    /// Registers an additional transport adapter.
    ///
    /// The adapter is appended to the end of the adapter list. In Phase 1,
    /// only the first adapter is used for send/query/delete operations.
    /// Multi-adapter routing is Phase 2+.
    pub fn add_adapter(&mut self, adapter: Box<dyn TransportAdapter>) {
        self.adapters.push(adapter);
    }

    /// Returns the number of registered adapters.
    #[must_use]
    pub fn adapter_count(&self) -> usize {
        self.adapters.len()
    }

    /// Send an outer envelope through the registered adapters.
    ///
    /// **Phase 1:** Routes through the first adapter only.
    /// **Phase 2+:** Routes through one or more adapters based on policy.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no adapters are registered.
    /// Propagates errors from the underlying adapter.
    pub async fn send(&self, envelope: &OuterEnvelope) -> Result<BlobId, TransportError> {
        let adapter = self.adapters.first().ok_or(TransportError::NotConnected)?;

        adapter.send(envelope).await
    }

    /// Subscribe to envelopes for a given routing ID across all adapters.
    ///
    /// Returns a merged stream that yields [`TransportEvent`]s from all
    /// registered adapters. Envelope events are deduplicated by [`BlobId`]
    /// (computed from the envelope's wire bytes). Control events
    /// ([`BackfillComplete`](TransportEvent::BackfillComplete),
    /// [`Reconnected`](TransportEvent::Reconnected),
    /// [`Terminated`](TransportEvent::Terminated),
    /// [`Error`](TransportEvent::Error)) are passed through per-adapter.
    ///
    /// **Phase 1:** With a single adapter, the stream is passed through
    /// directly (no merging or deduplication needed).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no adapters are registered.
    /// Returns [`TransportError::SubscriptionFailed`] if any adapter's
    /// subscription fails.
    pub async fn subscribe(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> Result<SubscriptionStream, TransportError> {
        if self.adapters.is_empty() {
            return Err(TransportError::NotConnected);
        }

        // Collect subscription streams from all adapters.
        let mut streams: Vec<SubscriptionStream> = Vec::with_capacity(self.adapters.len());

        for adapter in &self.adapters {
            let stream = adapter.subscribe(routing_id, since).await?;
            streams.push(stream);
        }

        // Phase 1 optimization: single adapter, no merging needed.
        if streams.len() == 1 {
            // SAFETY: we checked len() == 1 above, so pop always succeeds.
            if let Some(stream) = streams.pop() {
                return Ok(stream);
            }
        }

        // Phase 2+: merge streams with deduplication by BlobId.
        let merged = MergedStream::new(streams);
        Ok(Box::pin(merged))
    }

    /// Unsubscribe from a routing ID across all adapters.
    ///
    /// Sends an unsubscribe request to every registered adapter. If any
    /// adapter fails, the first error is returned after attempting all
    /// adapters.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no adapters are registered.
    /// Returns the first error encountered from any adapter.
    pub async fn unsubscribe(&self, routing_id: &RoutingId) -> Result<(), TransportError> {
        if self.adapters.is_empty() {
            return Err(TransportError::NotConnected);
        }

        let mut first_error: Option<TransportError> = None;
        for adapter in &self.adapters {
            if let Err(e) = adapter.unsubscribe(routing_id).await
                && first_error.is_none()
            {
                first_error = Some(e);
            }
        }

        first_error.map_or(Ok(()), Err)
    }

    /// One-shot query for stored envelopes across all adapters.
    ///
    /// **Phase 1:** Queries the first adapter only.
    /// **Phase 2+:** Queries all adapters and merges results with
    /// deduplication.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no adapters are registered.
    /// Propagates errors from the underlying adapter.
    pub async fn query(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> Result<Vec<OuterEnvelope>, TransportError> {
        let adapter = self.adapters.first().ok_or(TransportError::NotConnected)?;

        adapter.query(routing_id, since).await
    }

    /// Request deletion of a blob across all adapters.
    ///
    /// Sends a delete request to every registered adapter. Best-effort:
    /// untrusted transports may ignore the request. If any adapter fails,
    /// the first error is returned after attempting all adapters.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::NotConnected`] if no adapters are registered.
    /// Returns the first error encountered from any adapter.
    pub async fn delete(&self, blob_id: &BlobId) -> Result<(), TransportError> {
        if self.adapters.is_empty() {
            return Err(TransportError::NotConnected);
        }

        let mut first_error: Option<TransportError> = None;
        for adapter in &self.adapters {
            if let Err(e) = adapter.delete(blob_id).await
                && first_error.is_none()
            {
                first_error = Some(e);
            }
        }

        first_error.map_or(Ok(()), Err)
    }
}

/// A merged stream that combines multiple adapter subscription streams with
/// deduplication by [`BlobId`] for [`TransportEvent::Envelope`] variants.
///
/// Control events ([`BackfillComplete`](TransportEvent::BackfillComplete),
/// [`Reconnected`](TransportEvent::Reconnected),
/// [`Terminated`](TransportEvent::Terminated),
/// [`Error`](TransportEvent::Error)) are passed through per-adapter without
/// deduplication.
struct MergedStream {
    /// The underlying adapter streams being merged.
    streams: Vec<SubscriptionStream>,
    /// Set of `BlobId`s already yielded, for deduplication.
    seen: HashSet<BlobId>,
}

impl MergedStream {
    /// Creates a new `MergedStream` from multiple adapter streams.
    fn new(streams: Vec<SubscriptionStream>) -> Self {
        Self {
            streams,
            seen: HashSet::new(),
        }
    }
}

impl Stream for MergedStream {
    type Item = TransportEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Round-robin poll across all streams. Return the first ready item
        // that passes deduplication. If all streams are pending, return
        // Pending. If all streams are exhausted, return None.
        let mut all_done = true;
        let mut any_pending = false;

        for stream in &mut this.streams {
            match stream.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => {
                    match &event {
                        TransportEvent::Envelope(envelope) => {
                            let blob_id = BlobId::from_sha256(&envelope.encrypted_blob);
                            if this.seen.insert(blob_id) {
                                return Poll::Ready(Some(event));
                            }
                            // Duplicate -- skip this event and continue polling.
                            // Wake immediately so we poll again.
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        // Control events are always passed through.
                        TransportEvent::Error(_)
                        | TransportEvent::BackfillComplete
                        | TransportEvent::Reconnected
                        | TransportEvent::Terminated { .. } => {
                            return Poll::Ready(Some(event));
                        }
                    }
                }
                Poll::Ready(None) => {
                    // This stream is exhausted.
                }
                Poll::Pending => {
                    all_done = false;
                    any_pending = true;
                }
            }
        }

        if all_done {
            Poll::Ready(None)
        } else if any_pending {
            Poll::Pending
        } else {
            // All streams returned Ready(None) -- we're done.
            Poll::Ready(None)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use futures::stream;
    use scp_core::envelope::create_outer_envelope;

    use super::*;

    /// A mock transport adapter for testing.
    struct MockAdapter {
        /// Envelopes stored by send().
        send_result: Result<BlobId, TransportError>,
        /// Envelopes returned by query().
        query_result: Result<Vec<OuterEnvelope>, TransportError>,
        /// Stream returned by subscribe().
        subscribe_events: Arc<Vec<TransportEvent>>,
    }

    impl MockAdapter {
        fn succeeding() -> Self {
            Self {
                send_result: Ok(BlobId::new([0xAA; 32])),
                query_result: Ok(Vec::new()),
                subscribe_events: Arc::new(Vec::new()),
            }
        }

        fn failing(error: TransportError) -> Self {
            Self {
                send_result: Err(error.clone()),
                query_result: Err(error),
                subscribe_events: Arc::new(Vec::new()),
            }
        }
    }

    impl TransportAdapter for MockAdapter {
        fn send(&self, _envelope: &OuterEnvelope) -> BoxFuture<'_, Result<BlobId, TransportError>> {
            let result = self.send_result.clone();
            Box::pin(async move { result })
        }

        fn subscribe(
            &self,
            _routing_id: &RoutingId,
            _since: Option<u64>,
        ) -> BoxFuture<'_, Result<SubscriptionStream, TransportError>> {
            let events = self.subscribe_events.clone();
            Box::pin(async move {
                // Create a stream from the stored events by cloning the envelope
                // data. We need to re-create TransportEvent because it's not Clone.
                let items: Vec<TransportEvent> = events
                    .iter()
                    .map(|e| match e {
                        TransportEvent::Envelope(env) => TransportEvent::Envelope(env.clone()),
                        TransportEvent::Error(err) => TransportEvent::Error(err.clone()),
                        TransportEvent::BackfillComplete => TransportEvent::BackfillComplete,
                        TransportEvent::Reconnected => TransportEvent::Reconnected,
                        TransportEvent::Terminated { reason } => TransportEvent::Terminated {
                            reason: reason.clone(),
                        },
                    })
                    .collect();
                let s: SubscriptionStream = Box::pin(stream::iter(items));
                Ok(s)
            })
        }

        fn unsubscribe(
            &self,
            _routing_id: &RoutingId,
        ) -> BoxFuture<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn query(
            &self,
            _routing_id: &RoutingId,
            _since: Option<u64>,
        ) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, TransportError>> {
            let result = self.query_result.clone();
            Box::pin(async move { result })
        }

        fn delete(&self, _blob_id: &BlobId) -> BoxFuture<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// Convenience type alias for the boxed future used in trait methods.
    type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

    fn test_envelope() -> OuterEnvelope {
        create_outer_envelope(&[0xAA; 32], None, 3600, vec![0x01, 0x02, 0x03]).unwrap()
    }

    #[tokio::test]
    async fn manager_new_has_one_adapter() {
        let manager = TransportManager::new(Box::new(MockAdapter::succeeding()));
        assert_eq!(manager.adapter_count(), 1);
    }

    #[tokio::test]
    async fn manager_builder_starts_empty() {
        let manager = TransportManager::builder();
        assert_eq!(manager.adapter_count(), 0);
    }

    #[tokio::test]
    async fn manager_add_adapter_increments_count() {
        let mut manager = TransportManager::builder();
        manager.add_adapter(Box::new(MockAdapter::succeeding()));
        assert_eq!(manager.adapter_count(), 1);
        manager.add_adapter(Box::new(MockAdapter::succeeding()));
        assert_eq!(manager.adapter_count(), 2);
    }

    #[tokio::test]
    async fn manager_send_returns_blob_id() {
        let manager = TransportManager::new(Box::new(MockAdapter::succeeding()));
        let envelope = test_envelope();
        let blob_id = manager.send(&envelope).await.unwrap();
        assert_eq!(blob_id, BlobId::new([0xAA; 32]));
    }

    #[tokio::test]
    async fn manager_send_no_adapters_returns_not_connected() {
        let manager = TransportManager::builder();
        let envelope = test_envelope();
        let result = manager.send(&envelope).await;
        assert!(matches!(result, Err(TransportError::NotConnected)));
    }

    #[tokio::test]
    async fn manager_send_propagates_adapter_error() {
        let manager = TransportManager::new(Box::new(MockAdapter::failing(
            TransportError::SendFailed("mock failure".to_string()),
        )));
        let envelope = test_envelope();
        let result = manager.send(&envelope).await;
        assert!(matches!(result, Err(TransportError::SendFailed(_))));
    }

    #[tokio::test]
    async fn manager_query_returns_envelopes() {
        let mut adapter = MockAdapter::succeeding();
        let env = test_envelope();
        adapter.query_result = Ok(vec![env]);

        let manager = TransportManager::new(Box::new(adapter));
        let routing_id = RoutingId::new([0xAA; 32]);
        let envelopes = manager.query(&routing_id, None).await.unwrap();
        assert_eq!(envelopes.len(), 1);
    }

    #[tokio::test]
    async fn manager_query_no_adapters_returns_not_connected() {
        let manager = TransportManager::builder();
        let routing_id = RoutingId::new([0xAA; 32]);
        let result = manager.query(&routing_id, None).await;
        assert!(matches!(result, Err(TransportError::NotConnected)));
    }

    #[tokio::test]
    async fn manager_subscribe_no_adapters_returns_not_connected() {
        let manager = TransportManager::builder();
        let routing_id = RoutingId::new([0xAA; 32]);
        let result = manager.subscribe(&routing_id, None).await;
        assert!(matches!(result, Err(TransportError::NotConnected)));
    }

    #[tokio::test]
    async fn manager_subscribe_single_adapter_yields_events() {
        let envelope = test_envelope();
        let adapter = MockAdapter {
            send_result: Ok(BlobId::new([0xAA; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![
                TransportEvent::Envelope(envelope),
                TransportEvent::BackfillComplete,
            ]),
        };

        let manager = TransportManager::new(Box::new(adapter));
        let routing_id = RoutingId::new([0xAA; 32]);
        let mut stream = manager.subscribe(&routing_id, Some(0)).await.unwrap();

        let first = stream.next().await;
        assert!(matches!(first, Some(TransportEvent::Envelope(_))));

        let second = stream.next().await;
        assert!(matches!(second, Some(TransportEvent::BackfillComplete)));

        let third = stream.next().await;
        assert!(third.is_none());
    }

    #[tokio::test]
    async fn manager_unsubscribe_no_adapters_returns_not_connected() {
        let manager = TransportManager::builder();
        let routing_id = RoutingId::new([0xAA; 32]);
        let result = manager.unsubscribe(&routing_id).await;
        assert!(matches!(result, Err(TransportError::NotConnected)));
    }

    #[tokio::test]
    async fn manager_unsubscribe_single_adapter_succeeds() {
        let manager = TransportManager::new(Box::new(MockAdapter::succeeding()));
        let routing_id = RoutingId::new([0xAA; 32]);
        let result = manager.unsubscribe(&routing_id).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn manager_delete_no_adapters_returns_not_connected() {
        let manager = TransportManager::builder();
        let blob_id = BlobId::new([0xAA; 32]);
        let result = manager.delete(&blob_id).await;
        assert!(matches!(result, Err(TransportError::NotConnected)));
    }

    #[tokio::test]
    async fn manager_delete_single_adapter_succeeds() {
        let manager = TransportManager::new(Box::new(MockAdapter::succeeding()));
        let blob_id = BlobId::new([0xAA; 32]);
        let result = manager.delete(&blob_id).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn merged_stream_deduplicates_envelopes() {
        let envelope = test_envelope();
        let envelope_clone = envelope.clone();

        // Two adapters returning the same envelope.
        let adapter1 = MockAdapter {
            send_result: Ok(BlobId::new([0xAA; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![TransportEvent::Envelope(envelope)]),
        };
        let adapter2 = MockAdapter {
            send_result: Ok(BlobId::new([0xBB; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![TransportEvent::Envelope(envelope_clone)]),
        };

        let mut manager = TransportManager::builder();
        manager.add_adapter(Box::new(adapter1));
        manager.add_adapter(Box::new(adapter2));

        let routing_id = RoutingId::new([0xAA; 32]);
        let mut stream = manager.subscribe(&routing_id, None).await.unwrap();

        // Should get exactly one envelope (the duplicate is deduplicated).
        let first = stream.next().await;
        assert!(matches!(first, Some(TransportEvent::Envelope(_))));

        // The stream should end after the single envelope.
        let remaining = stream.next().await;
        assert!(remaining.is_none());
    }

    #[tokio::test]
    async fn merged_stream_passes_control_events_through() {
        let adapter1 = MockAdapter {
            send_result: Ok(BlobId::new([0xAA; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![TransportEvent::BackfillComplete]),
        };
        let adapter2 = MockAdapter {
            send_result: Ok(BlobId::new([0xBB; 32])),
            query_result: Ok(Vec::new()),
            subscribe_events: Arc::new(vec![TransportEvent::BackfillComplete]),
        };

        let mut manager = TransportManager::builder();
        manager.add_adapter(Box::new(adapter1));
        manager.add_adapter(Box::new(adapter2));

        let routing_id = RoutingId::new([0xAA; 32]);
        let mut stream = manager.subscribe(&routing_id, Some(0)).await.unwrap();

        // Both BackfillComplete events should pass through (one per adapter).
        let first = stream.next().await;
        assert!(matches!(first, Some(TransportEvent::BackfillComplete)));

        let second = stream.next().await;
        assert!(matches!(second, Some(TransportEvent::BackfillComplete)));
    }
}
