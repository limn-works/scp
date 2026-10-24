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
//! The `is_connected` method stays **sync**: it reads an `AtomicBool`
//! (ADR-049 Decision 7 `is_connected`-stays-sync carve-out). The flag is
//! `true` from construction and changes only through
//! [`RelayTransportProvider::mark_disconnected`] and
//! [`RelayTransportProvider::mark_connected`], which no adapter path calls, so
//! it does not report whether the relay is reachable now.
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
use scp_protocol::envelope::outer::BlobTtl;

use crate::traits::{BlobId, TransportAdapter};

/// Blob TTL in seconds (1 hour) for the two non-message publishes:
/// the context-announcement placeholder (`publish_context`) and a published
/// `KeyPackage` (`publish_key_package`).
///
/// MLS messages to a context do not use it: [`send_message`] requests the
/// [`BlobTtl`] the runtime chose from the message's type
/// (`09-security-model.md` §9.10.2 "Blob TTL by message type").
///
/// [`send_message`]: ContextTransportProvider::send_message
const DEFAULT_BLOB_TTL: u32 = 3600;

/// Production [`ContextTransportProvider`] wrapping a [`TransportAdapter`].
///
/// Provides context publication, deletion, and message sending by delegating
/// to the underlying transport adapter. Its `is_connected` flag reports only
/// what the last `mark_*` call set, `true` from construction; it never probes
/// the relay.
///
/// # Construction
///
/// ```rust,ignore
/// use scp_transport::native::adapter::{CoverTraffic, NativeRelayAdapter};
/// use scp_transport::provider::RelayTransportProvider;
///
/// let adapter = NativeRelayAdapter::connect_sourced(&sourced_url, None, CoverTraffic::Off).await?;
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
    /// The connection flag `is_connected` returns: `true` from construction,
    /// changed only by [`Self::mark_disconnected`] and
    /// [`Self::mark_connected`]. No adapter path calls either, so the flag
    /// does not follow the adapter's live connection.
    connected: AtomicBool,
}

impl<A: TransportAdapter + Send + Sync + 'static> RelayTransportProvider<A> {
    /// Creates a new `RelayTransportProvider` wrapping the given adapter.
    ///
    /// The provider starts with its connection flag set: the caller passes an
    /// adapter that already connected. The flag does not change when that
    /// adapter later loses its connection.
    #[must_use]
    pub fn new(adapter: A) -> Self {
        Self {
            adapter: Arc::new(adapter),
            connected: AtomicBool::new(true),
        }
    }

    /// Clears the connection flag, so `is_connected()` returns `false` until
    /// [`mark_connected`](Self::mark_connected) sets it again.
    ///
    /// No adapter path calls this method; a caller that observes the adapter
    /// losing its connection calls it.
    pub fn mark_disconnected(&self) {
        self.connected.store(false, Ordering::Release);
    }

    /// Sets the connection flag, so `is_connected()` returns `true`.
    ///
    /// No adapter path calls this method; a caller that reconnected the
    /// adapter calls it.
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
        ttl: BlobTtl,
    ) -> Result<(), ContextError> {
        // The one framing of a member publish (ADR-002, spec 23 §23.4.1): the
        // payload is the serialized MLS message, and this envelope is the only
        // one around it. The `blob_ttl` is the one the runtime chose from the
        // message's type (`09-security-model.md` §9.10.2 "Blob TTL by message
        // type"); the provider never picks its own.
        let envelope = scp_core::envelope::OuterEnvelope::frame_mls_message(
            context_id,
            None,
            ttl,
            encrypted_payload.to_vec(),
        )
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
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

    use std::sync::atomic::{AtomicU32, AtomicUsize};

    use futures::future::BoxFuture;

    use crate::traits::{RoutingId, SubscriptionStream};

    /// Minimal test adapter that records calls.
    struct TestAdapter {
        send_count: AtomicUsize,
        delete_count: AtomicUsize,
        fail_send: AtomicBool,
        /// `blob_ttl` of the last envelope passed to `send`.
        last_blob_ttl: AtomicU32,
    }

    impl TestAdapter {
        fn new() -> Self {
            Self {
                send_count: AtomicUsize::new(0),
                delete_count: AtomicUsize::new(0),
                fail_send: AtomicBool::new(false),
                last_blob_ttl: AtomicU32::new(0),
            }
        }
    }

    impl TransportAdapter for TestAdapter {
        fn send(
            &self,
            envelope: &OuterEnvelope,
        ) -> BoxFuture<'_, Result<BlobId, crate::TransportError>> {
            self.send_count.fetch_add(1, Ordering::Relaxed);
            self.last_blob_ttl
                .store(envelope.blob_ttl, Ordering::Relaxed);
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

        let result = provider
            .send_message(
                &ctx_id,
                b"encrypted-payload",
                BlobTtl::fresh(scp_protocol::envelope::outer::BlobClass::Message),
            )
            .await;
        assert!(result.is_ok());

        let count = provider.adapter.send_count.load(Ordering::Relaxed);
        assert_eq!(count, 1);
    }

    /// Every MLS message the native runtime publishes goes through
    /// `send_message`, and the frame carries the `BlobTtl` the runtime chose
    /// (`09-security-model.md` §9.10.2 "Blob TTL by message type").
    #[tokio::test]
    async fn send_message_frames_the_requested_blob_ttl() {
        use scp_protocol::envelope::outer::BlobClass;
        let provider = RelayTransportProvider::new(TestAdapter::new());

        for (class, want) in [
            (BlobClass::Message, scp_relay_client::MAX_BLOB_TTL),
            (BlobClass::Heartbeat, 240),
            (BlobClass::ConsistencyCheckpoint, 1_200),
        ] {
            provider
                .send_message(&[6u8; 32], b"mls-message", BlobTtl::fresh(class))
                .await
                .unwrap();
            let ttl = provider.adapter.last_blob_ttl.load(Ordering::Relaxed);
            assert_eq!(ttl, want, "{class:?}");
        }
    }

    /// The two non-message publishes keep their own one-hour TTL.
    #[tokio::test]
    async fn non_message_publishes_keep_the_one_hour_blob_ttl() {
        let provider = RelayTransportProvider::new(TestAdapter::new());

        provider
            .publish_context(&[7u8; 32], &ContextParams::default())
            .await
            .unwrap();
        assert_eq!(provider.adapter.last_blob_ttl.load(Ordering::Relaxed), 3600);

        provider
            .publish_key_package("did:dht:example", b"kp")
            .await
            .unwrap();
        assert_eq!(provider.adapter.last_blob_ttl.load(Ordering::Relaxed), 3600);
    }

    #[tokio::test]
    async fn send_message_returns_error_on_failure() {
        let adapter = TestAdapter::new();
        adapter.fail_send.store(true, Ordering::Relaxed);
        let provider = RelayTransportProvider::new(adapter);
        let ctx_id = [5u8; 32];

        let result = provider
            .send_message(
                &ctx_id,
                b"data",
                scp_protocol::envelope::outer::BlobTtl::fresh(
                    scp_protocol::envelope::outer::BlobClass::Message,
                ),
            )
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::TransportFailed(_)
        ));
    }
}
