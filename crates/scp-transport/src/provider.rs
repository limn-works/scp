//! Production [`ContextTransportProvider`] wrapping `NativeRelayAdapter`.
//!
//! [`RelayTransportProvider`] implements the async
//! [`ContextTransportProvider`] trait from `scp-core` by wrapping a
//! `NativeRelayAdapter` (or any [`TransportAdapter`]) and `.await`ing the
//! adapter's async transport operations directly.
//!
//! # Design (ADR-049 Decision 7)
//!
//! The I/O [`ContextTransportProvider`] trait methods are `async` and simply
//! `.await` the underlying async [`TransportAdapter`] — there is NO
//! `block_in_place` / `Handle::block_on` sync→async bridge. Because every
//! [`TransportAdapter`] method takes `&self`, the adapter is held behind a
//! plain `Arc<A>` (no `Mutex`): concurrent sends share `&A` directly and the
//! resulting futures stay `Send`, so the provider is safe to hold as
//! `Arc<dyn ContextTransportProvider>` in `ActorDeps` (moved into
//! `tokio::spawn`).
//!
//! The `is_connected` method stays **sync** — it tracks connection state via
//! an `AtomicBool` set during construction or reconnection (ADR-049 Decision 7
//! `is_connected`-stays-sync carve-out).
//!
//! # Thread Safety
//!
//! `RelayTransportProvider` is `Send + Sync`. The underlying adapter is stored
//! in an `Arc<A>`; all adapter operations take `&self`.
//!
//! See ADR-005 (transport abstraction), ADR-008 (context creation).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use scp_core::context::builder::{ContextCreationError, ContextTransportProvider};
use scp_core::context::{ContextError, ContextParams};
use scp_core::crypto::envelope_seal::derive_key_package_routing_id;
use scp_core::envelope::OuterEnvelope;

use crate::traits::{BlobId, TransportAdapter};

/// Default blob TTL in seconds (1 hour) for relay-published envelopes.
///
/// The relay enforces `MIN_BLOB_TTL..=MAX_BLOB_TTL` (1..=604800). A TTL of 0
/// is rejected with relay error 4011. 3600 seconds (1 hour) matches the
/// standard default used across the codebase (`scp-node`, adapter tests,
/// protocol tests).
const DEFAULT_BLOB_TTL: u32 = 3600;

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
/// let adapter = NativeRelayAdapter::connect_sourced(&sourced_url, None).await?;
/// let transport = RelayTransportProvider::new(adapter);
/// let manager = ContextManager::new(
///     Box::new(crypto),
///     Box::new(transport),
///     Box::new(event_log),
/// );
/// ```
pub struct RelayTransportProvider<A: TransportAdapter + Send + Sync + 'static> {
    /// The underlying transport adapter. Held behind a plain `Arc` (no
    /// `Mutex`): every [`TransportAdapter`] method takes `&self`, so the
    /// async provider methods share `&A` and `.await` directly.
    adapter: Arc<A>,
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
            adapter: Arc::new(adapter),
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

    /// Build an [`OuterEnvelope`] for `routing_id` carrying `blob`.
    ///
    /// Centralizes the envelope-construction boilerplate the four publish /
    /// send paths share (version, default TTL, empty extensions, no
    /// recipient-hint / version-compatibility).
    fn build_envelope(routing_id: Vec<u8>, blob: Vec<u8>) -> OuterEnvelope {
        OuterEnvelope {
            version: scp_core::envelope::SCP_PROTOCOL_VERSION,
            routing_id,
            recipient_hint: None,
            blob_ttl: DEFAULT_BLOB_TTL,
            encrypted_blob: blob,
            extensions: std::collections::HashMap::new(),
            version_compatibility: None,
        }
    }

    /// `.await` the async adapter `send`, mapping a transport failure into a
    /// typed [`ContextError::TransportFailed`].
    ///
    /// Every [`TransportAdapter`] method takes `&self`, so this shares `&A`
    /// through the `Arc` and awaits the adapter future directly — no
    /// `block_in_place`, and the future is `Send`.
    async fn send_via_adapter(&self, envelope: &OuterEnvelope) -> Result<BlobId, ContextError> {
        self.adapter
            .send(envelope)
            .await
            .map_err(|e| ContextError::TransportFailed(e.to_string()))
    }
}

#[async_trait::async_trait]
impl<A: TransportAdapter + Send + Sync + 'static> ContextTransportProvider
    for RelayTransportProvider<A>
{
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    async fn publish_context(
        &self,
        context_id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        // Context announcements carry a minimal 1-byte placeholder blob because
        // the relay rejects empty blobs. The actual context parameters are not
        // published (they are exchanged via the invite/join flow). The
        // routing_id is the context_id itself (used by relays for routing).
        let envelope = Self::build_envelope(context_id.to_vec(), vec![0x00]);
        self.send_via_adapter(&envelope)
            .await
            .map(|_blob_id| ())
            .map_err(|e| ContextCreationError::TransportFailed(e.to_string()))
    }

    async fn delete_published(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let blob_id = BlobId::from_sha256(context_id);
        self.adapter
            .delete(&blob_id)
            .await
            .map_err(|e| ContextCreationError::TransportFailed(e.to_string()))
    }

    async fn send_message(
        &self,
        context_id: &[u8; 32],
        encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        let envelope = Self::build_envelope(context_id.to_vec(), encrypted_payload.to_vec());
        self.send_via_adapter(&envelope).await.map(|_blob_id| ())
    }

    async fn publish_key_package(
        &self,
        owner_did: &str,
        kp_bytes: &[u8],
    ) -> Result<(), ContextError> {
        // Route the published KeyPackage under the CANONICAL per-DID routing id
        // `derive_key_package_routing_id(owner_did)` (spec §5.12.3), so a peer
        // fetches this identity's KeyPackages with the SAME id the canonical
        // fetcher computes from the owner DID. The bytes land on this adapter's
        // own connection — there is no per-relay-URL fan-out. The
        // content-addressed blob keeps a re-publish of identical bytes
        // idempotent at the relay.
        let routing_id = derive_key_package_routing_id(owner_did);
        let envelope = Self::build_envelope(routing_id.to_vec(), kp_bytes.to_vec());
        self.send_via_adapter(&envelope).await.map(|_blob_id| ())
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

    // Async provider methods run on a plain `current_thread` runtime — no
    // `block_in_place`, so no multi-thread requirement (ADR-049 Decision 7).
    #[tokio::test]
    async fn publish_context_sends_envelope() {
        let adapter = TestAdapter::new();
        let provider = RelayTransportProvider::new(adapter);
        let ctx_id = [1u8; 32];

        let result = provider
            .publish_context(&ctx_id, &ContextParams::default())
            .await;
        assert!(result.is_ok());

        let count = provider.adapter.send_count.load(Ordering::Relaxed);
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn publish_context_returns_error_on_send_failure() {
        let adapter = TestAdapter::new();
        adapter.fail_send.store(true, Ordering::Relaxed);
        let provider = RelayTransportProvider::new(adapter);
        let ctx_id = [2u8; 32];

        let result = provider
            .publish_context(&ctx_id, &ContextParams::default())
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::TransportFailed(_)
        ));
    }

    #[tokio::test]
    async fn delete_published_sends_delete() {
        let adapter = TestAdapter::new();
        let provider = RelayTransportProvider::new(adapter);
        let ctx_id = [3u8; 32];

        let result = provider.delete_published(&ctx_id).await;
        assert!(result.is_ok());

        let count = provider.adapter.delete_count.load(Ordering::Relaxed);
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn send_message_delivers_payload() {
        let adapter = TestAdapter::new();
        let provider = RelayTransportProvider::new(adapter);
        let ctx_id = [4u8; 32];

        let result = provider.send_message(&ctx_id, b"encrypted-payload").await;
        assert!(result.is_ok());

        let count = provider.adapter.send_count.load(Ordering::Relaxed);
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn send_message_returns_error_on_failure() {
        let adapter = TestAdapter::new();
        adapter.fail_send.store(true, Ordering::Relaxed);
        let provider = RelayTransportProvider::new(adapter);
        let ctx_id = [5u8; 32];

        let result = provider.send_message(&ctx_id, b"data").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::TransportFailed(_)
        ));
    }
}
