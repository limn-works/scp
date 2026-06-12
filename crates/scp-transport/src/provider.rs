//! Production [`ContextTransportProvider`] wrapping `NativeRelayAdapter`.
//!
//! [`RelayTransportProvider`] implements the synchronous
//! [`ContextTransportProvider`] trait from `scp-core` by wrapping a
//! `NativeRelayAdapter` (or any [`TransportAdapter`]) and bridging
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

    /// Bridge the async adapter `send` to the synchronous
    /// [`ContextTransportProvider`] surface WITHOUT panicking on a
    /// `current_thread` runtime.
    ///
    /// `tokio::task::block_in_place` requires a multi-thread runtime: on a
    /// `current_thread` runtime it PANICS (`can call blocking only when
    /// running on the multi-threaded runtime`), and that panic is reachable
    /// from production (any node driven by a `current_thread` runtime), so it
    /// must be turned into a typed error rather than an unwind. We probe the
    /// current runtime's flavor first and return
    /// [`ContextError::TransportFailed`] on `current_thread`, only entering
    /// `block_in_place` when the multi-thread flavor makes it safe.
    fn send_blocking(&self, envelope: &OuterEnvelope) -> Result<BlobId, ContextError> {
        // Shared runtime-flavor probe: `block_in_place` panics on a
        // `current_thread` runtime (a reachable production crash), so guard it
        // and surface a typed error. `op` is the description for the typed
        // error messages.
        require_multi_thread_runtime("send").map_err(ContextError::TransportFailed)?;
        let adapter = Arc::clone(&self.adapter);
        // ci-allow: block-on: multi-thread runtime only — flavor is checked
        // above; current_thread returns a typed error instead of panicking.
        // Sync ContextTransportProvider surface bridges to the async adapter
        // here.
        tokio::task::block_in_place(|| {
            let guard = adapter
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            tokio::runtime::Handle::current().block_on(guard.send(envelope))
        })
        .map_err(|e| ContextError::TransportFailed(e.to_string()))
    }
}

/// Probe the current tokio runtime and require the multi-thread flavor.
///
/// `tokio::task::block_in_place` PANICS on a `current_thread` runtime (a
/// reachable production crash from any node driven by a `current_thread`
/// runtime), so every sync→async bridge in this provider must check the flavor
/// FIRST and return a typed error instead of unwinding. `op` names the
/// operation for the error text (e.g. `"send"`, `"delete"`).
///
/// Returns `Ok(())` only on a multi-thread runtime; otherwise an `Err(String)`
/// the caller maps into its own transport-error type.
fn require_multi_thread_runtime(op: &str) -> Result<(), String> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            Ok(())
        }
        Ok(_) => Err(format!(
            "transport {op} requires a multi-thread tokio runtime; \
             a current_thread runtime cannot bridge the sync→async boundary"
        )),
        Err(_) => Err(format!("transport {op} called outside a tokio runtime")),
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
        // Context announcements carry a minimal 1-byte placeholder blob because
        // the relay rejects empty blobs. The actual context parameters are not
        // published (they are exchanged via the invite/join flow). The
        // routing_id is the context_id itself (used by relays for routing).
        let envelope = Self::build_envelope(context_id.to_vec(), vec![0x00]);
        self.send_blocking(&envelope)
            .map(|_blob_id| ())
            .map_err(|e| ContextCreationError::TransportFailed(e.to_string()))
    }

    fn delete_published(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        let blob_id = BlobId::from_sha256(context_id);

        // Shared runtime-flavor probe (see `require_multi_thread_runtime`):
        // block_in_place panics on a current_thread runtime, so guard it and
        // surface a typed error instead.
        require_multi_thread_runtime("delete").map_err(ContextCreationError::TransportFailed)?;

        let adapter = Arc::clone(&self.adapter);
        let result = tokio::task::block_in_place(|| {
            let guard = adapter
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // ci-allow: block-on: multi-thread runtime only (flavor checked
            // above); sync ContextTransportProvider surface bridges to the
            // async adapter delete here.
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
        let envelope = Self::build_envelope(context_id.to_vec(), encrypted_payload.to_vec());
        self.send_blocking(&envelope).map(|_blob_id| ())
    }

    fn publish_key_package(&self, owner_did: &str, kp_bytes: &[u8]) -> Result<(), ContextError> {
        // Route the published KeyPackage under the CANONICAL per-DID routing id
        // `derive_key_package_routing_id(owner_did)` (spec §5.12.3), so a peer
        // fetches this identity's KeyPackages with the SAME id the canonical
        // fetcher computes from the owner DID. The bytes land on this adapter's
        // own connection — there is no per-relay-URL fan-out. The
        // content-addressed blob keeps a re-publish of identical bytes
        // idempotent at the relay.
        let routing_id = derive_key_package_routing_id(owner_did);
        let envelope = Self::build_envelope(routing_id.to_vec(), kp_bytes.to_vec());
        self.send_blocking(&envelope).map(|_blob_id| ())
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
