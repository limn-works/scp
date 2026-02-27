//! Standing channels (contact graph) for SCP.
//!
//! Standing bilateral contexts serve as the real-time communication primitive
//! (spec section 5.12.4). The SDK manages them as persistent infrastructure --
//! the agent's contact list. `standing_channel(peer_did)` is a get-or-create
//! operation that returns an existing `bilateral-persistent` context or creates
//! one. Idempotent.
//!
//! On SDK initialization, [`StandingChannelManager::reconnect_all`] reconnects
//! transport for all standing channels. Standing channels are available
//! immediately after `sdk.init()` returns.
//!
//! See `.docs/standards/sdk-common.md` section "Standing channels (contact
//! graph)" for the authoritative specification.
//!
//! # SCP-138

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use super::builder::{ContextCryptoProvider, ContextEventLogProvider, ContextTransportProvider};
use super::templates::template_params;
use super::{ContextError, ContextHandle, ContextState, TemplateId};
use crate::identity::DID;

// ---------------------------------------------------------------------------
// StandingChannelError
// ---------------------------------------------------------------------------

/// Errors specific to standing channel operations.
#[derive(Debug, thiserror::Error)]
pub enum StandingChannelError {
    /// Context creation failed during standing channel setup.
    #[error("context creation failed: {0}")]
    CreationFailed(String),

    /// Transport reconnection failed for a standing channel.
    #[error("transport reconnection failed for context {context_id}: {reason}")]
    ReconnectFailed {
        /// The context ID that failed to reconnect.
        context_id: String,
        /// The reason for the failure.
        reason: String,
    },
}

impl From<StandingChannelError> for ContextError {
    fn from(err: StandingChannelError) -> Self {
        ContextError::TransportFailed(err.to_string())
    }
}

// ---------------------------------------------------------------------------
// StandingChannelEntry -- internal per-channel tracking
// ---------------------------------------------------------------------------

/// Internal entry tracking a standing channel with a peer.
#[derive(Debug, Clone)]
struct StandingChannelEntry {
    /// The peer DID this standing channel is with.
    /// Retained for future peer enumeration and diagnostics.
    #[allow(dead_code)]
    peer_did: DID,
    /// The context handle for this standing channel.
    handle: ContextHandle,
}

// ---------------------------------------------------------------------------
// StandingChannelManager
// ---------------------------------------------------------------------------

/// Manages standing bilateral channels (the agent's contact graph).
///
/// Standing channels are `bilateral-persistent` contexts that persist across
/// sessions. The manager provides:
///
/// - [`standing_channel`](Self::standing_channel) -- Idempotent get-or-create.
/// - [`reconnect_all`](Self::reconnect_all) -- Startup transport reconnection.
///
/// # Thread Safety
///
/// `StandingChannelManager` is `Send + Sync`. Interior state is protected by
/// `tokio::sync::Mutex`.
pub struct StandingChannelManager {
    /// The local identity DID (creator of standing channels).
    local_did: DID,
    /// Crypto provider for context creation.
    crypto: Arc<dyn ContextCryptoProvider>,
    /// Transport provider for context creation and reconnection.
    transport: Arc<dyn ContextTransportProvider>,
    /// Event log provider for context creation.
    event_log: Arc<dyn ContextEventLogProvider>,
    /// Standing channels indexed by peer DID string.
    channels: Mutex<HashMap<String, StandingChannelEntry>>,
}

impl StandingChannelManager {
    /// Creates a new `StandingChannelManager`.
    ///
    /// # Arguments
    ///
    /// * `local_did` -- The DID of the local identity (channel creator).
    /// * `crypto` -- Crypto provider for MLS and sender key operations.
    /// * `transport` -- Transport provider for relay connectivity.
    /// * `event_log` -- Event log provider for event logging.
    #[must_use]
    pub fn new(
        local_did: DID,
        crypto: Arc<dyn ContextCryptoProvider>,
        transport: Arc<dyn ContextTransportProvider>,
        event_log: Arc<dyn ContextEventLogProvider>,
    ) -> Self {
        Self {
            local_did,
            crypto,
            transport,
            event_log,
            channels: Mutex::new(HashMap::new()),
        }
    }

    /// Returns an existing standing channel or creates a new one.
    ///
    /// This is the primary API for the contact graph. It follows four steps:
    ///
    /// 1. Check local state for an existing `bilateral-persistent` context
    ///    with this peer DID.
    /// 2. If found and `Active`, return it. Zero network cost -- instant.
    /// 3. If not found, create one (`bilateral-persistent` template), send
    ///    invitation, return the handle. First message queues until the peer
    ///    joins.
    /// 4. If found but peer has left (context is `Closed`, `Expired`, or
    ///    `Closing`), create a new one (re-invitation).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if context creation fails.
    pub async fn standing_channel(
        &self,
        peer_did: &DID,
    ) -> Result<ContextHandle, ContextError> {
        // Hold the lock across the entire get-or-create operation to prevent
        // TOCTOU races where two concurrent calls could both see "no channel"
        // and create duplicates.
        let mut channels = self.channels.lock().await;

        // Step 1: Check local state for an existing channel with this peer.
        if let Some(entry) = channels.get(peer_did.as_ref()) {
            let state = entry.handle.state().await;
            match state {
                // Step 2: Active -- return immediately, zero network cost.
                ContextState::Active => {
                    return Ok(entry.handle.clone());
                }
                // Step 4: Peer has left or context ended -- fall through to
                // create a new one.
                ContextState::Closed | ContextState::Expired | ContextState::Closing => {
                    // Will create a new channel below.
                }
                // Creating -- context is still being set up, return it.
                ContextState::Creating => {
                    return Ok(entry.handle.clone());
                }
            }
        }

        // Step 3/4: Create a new bilateral-persistent context.
        // Lock is held across creation to prevent duplicate channels.
        let handle = self.create_standing_channel(peer_did).await?;

        // Register the new channel (replacing any old entry).
        channels.insert(
            peer_did.to_string(),
            StandingChannelEntry {
                peer_did: peer_did.clone(),
                handle: handle.clone(),
            },
        );

        Ok(handle)
    }

    /// Reconnects transport for all active standing channels.
    ///
    /// Called during SDK initialization. Iterates all tracked standing channels
    /// and reconnects transport for those in the `Active` state. Channels in
    /// terminal states (`Closed`, `Expired`) are skipped.
    ///
    /// This is background work -- standing channels are available immediately
    /// after this method returns.
    ///
    /// # Returns
    ///
    /// The number of channels successfully reconnected.
    ///
    /// # Errors
    ///
    /// Returns [`StandingChannelError::ReconnectFailed`] if any reconnection
    /// fails. Partial reconnection results are still applied -- channels that
    /// succeeded remain connected.
    pub async fn reconnect_all(&self) -> Result<usize, StandingChannelError> {
        let channels = self.channels.lock().await;
        let mut reconnected = 0;

        for entry in channels.values() {
            let state = entry.handle.state().await;
            if state == ContextState::Active {
                let context_id = entry.handle.context_id();
                let context_id_bytes = super::context_id_bytes(context_id);
                // Reconnect transport by publishing the context (re-subscribing
                // to the relay for this context's messages).
                self.transport
                    .publish_context(&context_id_bytes, entry.handle.params())
                    .map_err(|e| StandingChannelError::ReconnectFailed {
                        context_id: context_id.to_owned(),
                        reason: e.to_string(),
                    })?;
                reconnected += 1;
            }
        }

        Ok(reconnected)
    }

    /// Returns the number of tracked standing channels.
    pub async fn channel_count(&self) -> usize {
        self.channels.lock().await.len()
    }

    /// Returns `true` if a standing channel exists for the given peer DID.
    pub async fn has_channel(&self, peer_did: &DID) -> bool {
        self.channels.lock().await.contains_key(peer_did.as_ref())
    }

    /// Registers an existing context as a standing channel.
    ///
    /// Used during startup to restore standing channels from persisted state.
    /// The context must be a `bilateral-persistent` context.
    pub async fn register_existing(&self, peer_did: DID, handle: ContextHandle) {
        let mut channels = self.channels.lock().await;
        channels.insert(
            peer_did.to_string(),
            StandingChannelEntry {
                peer_did,
                handle,
            },
        );
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Creates a new bilateral-persistent context for a standing channel.
    ///
    /// Uses the two-phase commit creation flow via the builder, then
    /// transitions the context to Active.
    async fn create_standing_channel(
        &self,
        peer_did: &DID,
    ) -> Result<ContextHandle, ContextError> {
        let context_id = generate_standing_channel_id(&self.local_did, peer_did);
        let params = template_params(&TemplateId::BilateralPersistent);

        // Use the builder's create_context for the two-phase commit flow.
        let handle = super::builder::create_context(
            context_id,
            params,
            self.crypto.as_ref(),
            self.transport.as_ref(),
            self.event_log.as_ref(),
        )
        .await
        .map_err(|e| ContextError::TransportFailed(e.to_string()))?;

        // The builder transitions the context to Active on success.
        // Send invitation to the peer via transport (the context announcement
        // published by the builder serves as the invitation for bilateral
        // contexts -- see sdk-common.md "Bilateral shorthand").

        Ok(handle)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generates a deterministic context ID for a standing channel between two DIDs.
///
/// The ID is derived from both DIDs sorted lexicographically, ensuring the same
/// channel ID is generated regardless of which peer initiates. Uses a
/// `standing:` prefix for namespace isolation and a truncated SHA-256 hash of
/// the sorted DID pair for the unique portion.
fn generate_standing_channel_id(local_did: &DID, peer_did: &DID) -> String {
    // Sort to ensure determinism regardless of direction.
    let (a, b) = if local_did.as_ref() <= peer_did.as_ref() {
        (local_did.as_ref(), peer_did.as_ref())
    } else {
        (peer_did.as_ref(), local_did.as_ref())
    };
    // Hash the sorted DIDs with the standing prefix for a stable, deterministic ID.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"standing:");
    hasher.update(a.as_bytes());
    hasher.update(b":");
    hasher.update(b.as_bytes());
    let hash = hasher.finalize();
    format!("standing-{}", hex::encode(&hash[..8]))
}

/// Minimal hex encoding for context ID generation.
mod hex {
    /// Encodes bytes as a lowercase hex string.
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// Compile-time assertion that `StandingChannelManager` is `Send + Sync`.
const fn _assert_send_sync() {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<StandingChannelManager>();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::context::builder::{
        ContextCreationError, ContextCryptoProvider, ContextEventLogProvider,
        ContextTransportProvider,
    };
    use crate::context::{ContextParams, ContextState};

    // -----------------------------------------------------------------------
    // Mock providers (mirrors manager.rs test mocks)
    // -----------------------------------------------------------------------

    #[derive(Default)]
    struct MockCrypto;

    impl ContextCryptoProvider for MockCrypto {
        fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn create_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn generate_sender_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn init_broadcast_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn destroy_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn destroy_sender_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn validate_key_package(&self, _owner_did: &str) -> Result<(), ContextError> {
            Ok(())
        }

        fn add_member(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }

        fn remove_member(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }

        fn distribute_sender_key(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }

        fn remove_member_sender_key(
            &self,
            _context_id: &[u8; 32],
            _member_did: &str,
        ) -> Result<(), ContextError> {
            Ok(())
        }

        fn encrypt_message(
            &self,
            _context_id: &[u8; 32],
            _sender_did: &str,
            payload: &[u8],
        ) -> Result<Vec<u8>, ContextError> {
            Ok(payload.to_vec())
        }
    }

    #[derive(Default)]
    struct MockTransport {
        connected: AtomicBool,
        publish_count: std::sync::Mutex<usize>,
    }

    impl MockTransport {
        fn connected() -> Self {
            let t = Self::default();
            t.connected.store(true, Ordering::Relaxed);
            t
        }

        fn publish_count(&self) -> usize {
            *self.publish_count.lock().unwrap()
        }
    }

    impl ContextTransportProvider for MockTransport {
        fn is_connected(&self) -> bool {
            self.connected.load(Ordering::Relaxed)
        }

        fn publish_context(
            &self,
            _id: &[u8; 32],
            _params: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            *self.publish_count.lock().unwrap() += 1;
            Ok(())
        }

        fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn send_message(
            &self,
            _context_id: &[u8; 32],
            _encrypted_payload: &[u8],
        ) -> Result<(), ContextError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockEventLog;

    impl ContextEventLogProvider for MockEventLog {
        fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn append_event(
            &self,
            _id: &[u8; 32],
            _event: &str,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Helper: create a manager with default mocks
    // -----------------------------------------------------------------------

    fn create_manager() -> (StandingChannelManager, Arc<MockTransport>) {
        let transport = Arc::new(MockTransport::connected());
        let manager = StandingChannelManager::new(
            DID::from("did:dht:z6MkLocalAlice"),
            Arc::new(MockCrypto::default()),
            transport.clone(),
            Arc::new(MockEventLog::default()),
        );
        (manager, transport)
    }

    // -----------------------------------------------------------------------
    // Test: standing_channel returns existing context without network call
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn standing_channel_returns_existing_active_context() {
        let (manager, transport) = create_manager();
        let bob = DID::from("did:dht:z6MkBob");

        // First call creates the channel.
        let handle1 = manager.standing_channel(&bob).await.unwrap();
        assert_eq!(handle1.state().await, ContextState::Active);

        // Record transport publish count after first creation.
        let publishes_after_create = transport.publish_count();

        // Second call should return the same handle without network cost.
        let handle2 = manager.standing_channel(&bob).await.unwrap();
        assert_eq!(handle2.context_id(), handle1.context_id());
        assert_eq!(handle2.state().await, ContextState::Active);

        // No additional transport publishes should have occurred.
        assert_eq!(transport.publish_count(), publishes_after_create);
    }

    // -----------------------------------------------------------------------
    // Test: standing_channel creates new bilateral-persistent context
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn standing_channel_creates_new_bilateral_persistent_context() {
        let (manager, _transport) = create_manager();
        let carol = DID::from("did:dht:z6MkCarol");

        assert!(!manager.has_channel(&carol).await);

        let handle = manager.standing_channel(&carol).await.unwrap();

        // Verify the context is Active.
        assert_eq!(handle.state().await, ContextState::Active);

        // Verify the context uses bilateral-persistent template params.
        let params = handle.params();
        assert_eq!(params.template_id, Some(TemplateId::BilateralPersistent));
        assert!(params.ttl.is_none()); // bilateral-persistent forbids TTL
        assert_eq!(params.memory_scope, super::super::params::MemoryScope::Full);

        // Verify the channel is now tracked.
        assert!(manager.has_channel(&carol).await);
        assert_eq!(manager.channel_count().await, 1);
    }

    // -----------------------------------------------------------------------
    // Test: standing_channel re-creates context when peer has left
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn standing_channel_recreates_when_peer_has_left() {
        let (manager, _transport) = create_manager();
        let dave = DID::from("did:dht:z6MkDave");

        // Create initial channel.
        let handle1 = manager.standing_channel(&dave).await.unwrap();
        assert_eq!(handle1.state().await, ContextState::Active);

        // Simulate peer leaving: transition to Closing -> Closed.
        handle1
            .transition_to(&ContextState::Closing)
            .await
            .unwrap();
        handle1.transition_to(&ContextState::Closed).await.unwrap();

        // Calling standing_channel again should create a new context.
        let handle2 = manager.standing_channel(&dave).await.unwrap();
        assert_eq!(handle2.state().await, ContextState::Active);

        // The new context should have a different ID (or same stable ID but
        // be a different handle -- in our implementation, the deterministic
        // ID generation means the context_id is stable, but the handle is
        // new and Active).
        // The key assertion: we get an Active handle back, not the Closed one.
        assert_eq!(handle2.state().await, ContextState::Active);

        // The old handle should still be Closed.
        assert_eq!(handle1.state().await, ContextState::Closed);

        // Verify the new handle is now tracked (replacing the old entry).
        assert_eq!(manager.channel_count().await, 1);
        assert!(manager.has_channel(&dave).await);
    }

    // -----------------------------------------------------------------------
    // Test: standing_channel re-creates when context expired
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn standing_channel_recreates_when_context_expired() {
        let (manager, _transport) = create_manager();
        let eve = DID::from("did:dht:z6MkEve");

        // Create initial channel.
        let handle1 = manager.standing_channel(&eve).await.unwrap();
        assert_eq!(handle1.state().await, ContextState::Active);

        // Simulate expiry.
        handle1
            .transition_to(&ContextState::Expired)
            .await
            .unwrap();

        // Calling standing_channel should create a new one.
        let handle2 = manager.standing_channel(&eve).await.unwrap();
        assert_eq!(handle2.state().await, ContextState::Active);
    }

    // -----------------------------------------------------------------------
    // Test: startup reconnection reconnects transport for all active channels
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn reconnect_all_reconnects_active_standing_channels() {
        let (manager, transport) = create_manager();

        // Create channels with multiple peers.
        let bob = DID::from("did:dht:z6MkBob");
        let carol = DID::from("did:dht:z6MkCarol");
        let dave = DID::from("did:dht:z6MkDave");

        let _h_bob = manager.standing_channel(&bob).await.unwrap();
        let h_carol = manager.standing_channel(&carol).await.unwrap();
        let _h_dave = manager.standing_channel(&dave).await.unwrap();

        // Close Carol's channel (simulating peer left).
        h_carol
            .transition_to(&ContextState::Closing)
            .await
            .unwrap();
        h_carol
            .transition_to(&ContextState::Closed)
            .await
            .unwrap();

        // Record current publish count (creation publishes context too).
        let publishes_before = transport.publish_count();

        // Reconnect all.
        let reconnected = manager.reconnect_all().await.unwrap();

        // Only Bob and Dave should be reconnected (Active). Carol is Closed.
        assert_eq!(reconnected, 2);

        // Transport should have been called twice more.
        assert_eq!(transport.publish_count(), publishes_before + 2);
    }

    // -----------------------------------------------------------------------
    // Test: reconnect_all with no channels returns zero
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn reconnect_all_with_no_channels_returns_zero() {
        let (manager, _transport) = create_manager();
        let reconnected = manager.reconnect_all().await.unwrap();
        assert_eq!(reconnected, 0);
    }

    // -----------------------------------------------------------------------
    // Test: idempotency -- multiple calls for same peer return same context
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn standing_channel_is_idempotent() {
        let (manager, _transport) = create_manager();
        let frank = DID::from("did:dht:z6MkFrank");

        let h1 = manager.standing_channel(&frank).await.unwrap();
        let h2 = manager.standing_channel(&frank).await.unwrap();
        let h3 = manager.standing_channel(&frank).await.unwrap();

        // All should return the same context_id.
        assert_eq!(h1.context_id(), h2.context_id());
        assert_eq!(h2.context_id(), h3.context_id());

        // Only one channel should be tracked.
        assert_eq!(manager.channel_count().await, 1);
    }

    // -----------------------------------------------------------------------
    // Test: register_existing allows pre-populating channels
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn register_existing_populates_channel() {
        let (manager, transport) = create_manager();
        let grace = DID::from("did:dht:z6MkGrace");

        // Create a handle externally and register it.
        let params = template_params(&TemplateId::BilateralPersistent);
        let handle = ContextHandle::new("existing-ctx".to_owned(), params);
        handle.transition_to(&ContextState::Active).await.unwrap();

        manager.register_existing(grace.clone(), handle.clone()).await;

        // standing_channel should return the pre-registered handle.
        let publishes_before = transport.publish_count();
        let returned = manager.standing_channel(&grace).await.unwrap();
        assert_eq!(returned.context_id(), "existing-ctx");
        assert_eq!(returned.state().await, ContextState::Active);

        // No new transport publishes (no context creation).
        assert_eq!(transport.publish_count(), publishes_before);
    }

    // -----------------------------------------------------------------------
    // Test: generate_standing_channel_id is deterministic and order-independent
    // -----------------------------------------------------------------------

    #[test]
    fn standing_channel_id_is_deterministic() {
        let alice = DID::from("did:dht:z6MkAlice");
        let bob = DID::from("did:dht:z6MkBob");

        let id1 = generate_standing_channel_id(&alice, &bob);
        let id2 = generate_standing_channel_id(&bob, &alice);

        // Same pair produces the same ID regardless of order.
        assert_eq!(id1, id2);

        // Different pairs produce different IDs.
        let carol = DID::from("did:dht:z6MkCarol");
        let id3 = generate_standing_channel_id(&alice, &carol);
        assert_ne!(id1, id3);
    }
}
