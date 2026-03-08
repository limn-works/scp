//! Production [`ContextTransportProvider`] wrapping [`NativeRelayAdapter`].
//!
//! [`RelayTransportProvider`] implements the synchronous
//! [`ContextTransportProvider`] trait from `scp-core` by wrapping a
//! [`NativeRelayAdapter`] (or any [`TransportAdapter`]) and bridging
//! async transport operations to synchronous calls using
//! `tokio::task::block_in_place`.
//!
//! # Design
//!
//! The [`ContextTransportProvider`] trait methods are synchronous (`&self`)
//! because they are called from within `ContextManager` operations that hold
//! `Mutex` guards. The underlying transport operations are async, so this
//! provider bridges the gap using `block_in_place` + `Handle::block_on`.
//!
//! The `is_connected` method tracks connection state via an `AtomicBool`
//! that is set during construction or reconnection.
//!
//! # Thread Safety
//!
//! `RelayTransportProvider` is `Send + Sync`. The underlying adapter is
//! stored in an `Arc<Mutex<_>>` to allow mutable access for send operations.
//!
//! See ADR-005 (transport abstraction), ADR-008 (context creation).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use scp_core::context::builder::{ContextCreationError, ContextTransportProvider};
use scp_core::context::{ContextError, ContextParams};
use scp_core::envelope::OuterEnvelope;

use crate::traits::{BlobId, TransportAdapter};

/// Production [`ContextTransportProvider`] wrapping a [`TransportAdapter`].
///
/// Provides relay connectivity checks, context publication, deletion, and
/// message sending by delegating to the underlying transport adapter.
///
/// # Construction
///
/// ```rust,ignore
/// use scp_transport::native::adapter::NativeRelayAdapter;
/// use scp_transport::provider::RelayTransportProvider;
///
/// let adapter = NativeRelayAdapter::connect_sourced(&sourced_url).await?;
/// let transport = RelayTransportProvider::new(adapter);
/// let manager = ContextManager::new(
///     Box::new(crypto),
///     Box::new(transport),
///     Box::new(event_log),
/// );
/// ```
pub struct RelayTransportProvider<A: TransportAdapter + Send + Sync + 'static> {
    /// The underlying transport adapter.
    adapter: Arc<Mutex<A>>,
    /// Whether the transport is currently connected.
    connected: AtomicBool,
}

impl<A: TransportAdapter + Send + Sync + 'static> RelayTransportProvider<A> {
    /// Creates a new `RelayTransportProvider` wrapping the given adapter.
    ///
    /// The provider starts in the connected state (the adapter was
    /// successfully connected during construction).
    #[must_use]
    pub fn new(adapter: A) -> Self {
        Self {
            adapter: Arc::new(Mutex::new(adapter)),
            connected: AtomicBool::new(true),
        }
    }

    /// Marks the provider as disconnected.
    ///
    /// Call this when the underlying transport connection is lost (e.g.,
    /// WebSocket close, network error). The provider will report
    /// `is_connected() == false` until [`mark_connected`](Self::mark_connected)
    /// is called.
    pub fn mark_disconnected(&self) {
        self.connected.store(false, Ordering::Release);
    }

    /// Marks the provider as connected.
    ///
    /// Call this after successfully reconnecting the underlying transport.
    pub fn mark_connected(&self) {
        self.connected.store(true, Ordering::Release);
    }
}

// Nursery lint — false-positives on lock guards across block boundaries.
#[allow(clippy::significant_drop_tightening)]
impl<A: TransportAdapter + Send + Sync + 'static> ContextTransportProvider
    for RelayTransportProvider<A>
{
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    fn publish_context(
        &self,
        context_id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        // Build an OuterEnvelope representing the context announcement.
        // The routing_id is the context_id itself (used by relays for routing).
        // blob_ttl of 0 means use relay default.
        let envelope = OuterEnvelope {
            version: scp_core::envelope::outer::SCP_OUTER_ENVELOPE_VERSION,
            routing_id: context_id.to_vec(),
            recipient_hint: None,
            blob_ttl: 0,
            encrypted_blob: Vec::new(), // Context announcement: empty blob.
        };

        // Clone the Arc so the mutex lock is acquired inside block_in_place,
        // avoiding holding a std::sync::Mutex guard across async I/O which
        // would block tokio worker threads on concurrent calls.
        let adapter = Arc::clone(&self.adapter);

        let result = tokio::task::block_in_place(|| {
            let guard = adapter
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            tokio::runtime::Handle::current().block_on(guard.send(&envelope))
        });

        match result {
            Ok(_blob_id) => Ok(()),
            Err(e) => Err(ContextCreationError::TransportFailed(e.to_string())),
        }
    }

    fn delete_published(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let blob_id = BlobId::from_sha256(context_id);

        let adapter = Arc::clone(&self.adapter);

        let result = tokio::task::block_in_place(|| {
            let guard = adapter
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            tokio::runtime::Handle::current().block_on(guard.delete(&blob_id))
        });

        match result {
            Ok(()) => Ok(()),
            Err(e) => Err(ContextCreationError::TransportFailed(e.to_string())),
        }
    }

    fn send_message(
        &self,
        context_id: &[u8; 32],
        encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        let envelope = OuterEnvelope {
            version: scp_core::envelope::outer::SCP_OUTER_ENVELOPE_VERSION,
            routing_id: context_id.to_vec(),
            recipient_hint: None,
            blob_ttl: 0,
            encrypted_blob: encrypted_payload.to_vec(),
        };

        let adapter = Arc::clone(&self.adapter);

        let result = tokio::task::block_in_place(|| {
            let guard = adapter
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            tokio::runtime::Handle::current().block_on(guard.send(&envelope))
        });

        match result {
            Ok(_blob_id) => Ok(()),
            Err(e) => Err(ContextError::TransportFailed(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicUsize;

    use futures::future::BoxFuture;

    use crate::traits::{RoutingId, SubscriptionStream};

    /// Minimal test adapter that records calls.
    struct TestAdapter {
        send_count: AtomicUsize,
        delete_count: AtomicUsize,
        fail_send: AtomicBool,
    }

    impl TestAdapter {
        fn new() -> Self {
            Self {
                send_count: AtomicUsize::new(0),
                delete_count: AtomicUsize::new(0),
                fail_send: AtomicBool::new(false),
            }
        }
    }

    impl TransportAdapter for TestAdapter {
        fn send(
            &self,
            _envelope: &OuterEnvelope,
        ) -> BoxFuture<'_, Result<BlobId, crate::TransportError>> {
            self.send_count.fetch_add(1, Ordering::Relaxed);
            if self.fail_send.load(Ordering::Relaxed) {
                Box::pin(async {
                    Err(crate::TransportError::SendFailed(
                        "test failure".to_string(),
                    ))
                })
            } else {
                Box::pin(async { Ok(BlobId::new([0u8; 32])) })
            }
        }

        fn subscribe(
            &self,
            _routing_id: &RoutingId,
            _since: Option<u64>,
        ) -> BoxFuture<'_, Result<SubscriptionStream, crate::TransportError>> {
            Box::pin(async {
                Err(crate::TransportError::ConnectionFailed(
                    "not implemented for test".to_string(),
                ))
            })
        }

        fn unsubscribe(
            &self,
            _routing_id: &RoutingId,
        ) -> BoxFuture<'_, Result<(), crate::TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn query(
            &self,
            _routing_id: &RoutingId,
            _since: Option<u64>,
        ) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, crate::TransportError>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn delete(&self, _blob_id: &BlobId) -> BoxFuture<'_, Result<(), crate::TransportError>> {
            self.delete_count.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn is_connected_reflects_state() {
        let adapter = TestAdapter::new();
        let provider = RelayTransportProvider::new(adapter);

        assert!(provider.is_connected());

        provider.mark_disconnected();
        assert!(!provider.is_connected());

        provider.mark_connected();
        assert!(provider.is_connected());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn publish_context_sends_envelope() {
        let adapter = TestAdapter::new();
        let provider = RelayTransportProvider::new(adapter);
        let ctx_id = [1u8; 32];

        let result = provider.publish_context(&ctx_id, &ContextParams::default());
        assert!(result.is_ok());

        let count = provider
            .adapter
            .lock()
            .unwrap()
            .send_count
            .load(Ordering::Relaxed);
        assert_eq!(count, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn publish_context_returns_error_on_send_failure() {
        let adapter = TestAdapter::new();
        adapter.fail_send.store(true, Ordering::Relaxed);
        let provider = RelayTransportProvider::new(adapter);
        let ctx_id = [2u8; 32];

        let result = provider.publish_context(&ctx_id, &ContextParams::default());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::TransportFailed(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn delete_published_sends_delete() {
        let adapter = TestAdapter::new();
        let provider = RelayTransportProvider::new(adapter);
        let ctx_id = [3u8; 32];

        let result = provider.delete_published(&ctx_id);
        assert!(result.is_ok());

        let count = provider
            .adapter
            .lock()
            .unwrap()
            .delete_count
            .load(Ordering::Relaxed);
        assert_eq!(count, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn send_message_delivers_payload() {
        let adapter = TestAdapter::new();
        let provider = RelayTransportProvider::new(adapter);
        let ctx_id = [4u8; 32];

        let result = provider.send_message(&ctx_id, b"encrypted-payload");
        assert!(result.is_ok());

        let count = provider
            .adapter
            .lock()
            .unwrap()
            .send_count
            .load(Ordering::Relaxed);
        assert_eq!(count, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn send_message_returns_error_on_failure() {
        let adapter = TestAdapter::new();
        adapter.fail_send.store(true, Ordering::Relaxed);
        let provider = RelayTransportProvider::new(adapter);
        let ctx_id = [5u8; 32];

        let result = provider.send_message(&ctx_id, b"data");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::TransportFailed(_)
        ));
    }
}
