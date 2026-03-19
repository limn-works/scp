//! Full-stack test node wrapping `ContextManager` with real crypto.
//!
//! Each `FullStackNode` owns a `ContextManager` backed by:
//! - [`E2eCryptoProvider`] — real MLS + sender keys with shared `KeyExchange`
//! - [`CapturingTransport`] — captures sent ciphertexts for retrieval by tests
//! - `MerkleEventLogProvider` — real Merkle-chained event log

use std::sync::{Arc, Mutex};

use scp_core::context::builder::{
    ContextCreationError, ContextCryptoProvider, ContextEventLogProvider, ContextTransportProvider,
};
use scp_core::context::governance::KeyResolver;
use scp_core::context::membership::{ContextEvent, KeyPackage};
use scp_core::context::providers::event_log::MerkleEventLogProvider;
use scp_core::context::{ContextError, ContextHandle, ContextManager, ContextParams};
use scp_identity::DID;

use super::crypto::E2eCryptoProvider;

// ---------------------------------------------------------------------------
// CapturingTransport — stores sent ciphertexts for test retrieval
// ---------------------------------------------------------------------------

/// Shared buffer of `(context_id, ciphertext)` pairs.
type SentBuffer = Arc<Mutex<Vec<([u8; 32], Vec<u8>)>>>;

/// Transport provider that captures sent ciphertexts in a shared buffer.
///
/// After `ContextManager::send_message` encrypts and "sends" a message,
/// the ciphertext is stored here. Tests retrieve it via
/// `FullStackNode::take_sent_ciphertexts` and feed it to the receiver's
/// `decrypt_message`.
#[derive(Clone)]
struct CapturingTransport {
    /// `(context_id, ciphertext)` pairs, in send order.
    sent: SentBuffer,
}

impl CapturingTransport {
    const fn new(sent: SentBuffer) -> Self {
        Self { sent }
    }
}

#[allow(clippy::significant_drop_tightening)]
impl ContextTransportProvider for CapturingTransport {
    fn is_connected(&self) -> bool {
        true
    }

    fn publish_context(
        &self,
        _context_id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn delete_published(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn send_message(
        &self,
        context_id: &[u8; 32],
        encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        let mut sent = self
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sent.push((*context_id, encrypted_payload.to_vec()));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FullStackNode
// ---------------------------------------------------------------------------

/// A test node with real `ContextManager`, real MLS crypto, and real event log.
///
/// Use `FullStackNetwork::create_node()` to construct nodes with a shared
/// `KeyExchange`.
pub struct FullStackNode {
    /// This node's DID.
    pub did: DID,
    /// The `ContextManager` with real crypto.
    pub manager: ContextManager,
    /// Direct access to the crypto provider for `join_from_welcome` and
    /// `decrypt_message` (methods not on the `ContextCryptoProvider` trait).
    pub crypto: Arc<E2eCryptoProvider>,
    /// The event log provider (for Merkle root verification in tests).
    pub event_log: Arc<MerkleEventLogProvider>,
    /// Sent ciphertexts captured by the transport, shared with the manager.
    sent: SentBuffer,
}

impl FullStackNode {
    /// Creates a new full-stack node.
    ///
    /// # Arguments
    ///
    /// * `did` - This node's DID.
    /// * `crypto` - The E2E crypto provider (shared `KeyExchange` inside).
    /// * `key_resolver` - Resolver for governance vote verification.
    #[must_use]
    pub fn new(did: DID, crypto: Arc<E2eCryptoProvider>, key_resolver: KeyResolver) -> Self {
        let event_log = Arc::new(MerkleEventLogProvider::new());
        let sent: SentBuffer = Arc::new(Mutex::new(Vec::new()));

        let crypto_box: Box<dyn ContextCryptoProvider> =
            Box::new(ArcCryptoProvider(Arc::clone(&crypto)));
        let event_log_box: Box<dyn ContextEventLogProvider> =
            Box::new(ArcEventLogProvider(Arc::clone(&event_log)));
        let transport_box: Box<dyn ContextTransportProvider> =
            Box::new(CapturingTransport::new(Arc::clone(&sent)));

        let manager = ContextManager::new(crypto_box, transport_box, event_log_box, key_resolver);

        Self {
            did,
            manager,
            crypto,
            event_log,
            sent,
        }
    }

    /// Creates a context and returns the handle.
    ///
    /// # Errors
    ///
    /// Propagates `ContextCreationError` from `ContextManager`.
    pub async fn create_context(
        &self,
        context_id: &str,
        params: ContextParams,
    ) -> Result<ContextHandle, ContextCreationError> {
        self.manager
            .create_context(context_id.to_owned(), params, self.did.clone())
            .await
    }

    /// Adds a member to the context (Alice-side operation).
    ///
    /// This calls `join_context` on the manager, which internally calls
    /// `crypto.add_member` (capturing the Welcome) and
    /// `crypto.distribute_sender_key` (depositing the sender key).
    ///
    /// # Errors
    ///
    /// Propagates `ContextError` from `ContextManager`.
    pub async fn add_member(
        &self,
        handle: &ContextHandle,
        member_did: &str,
    ) -> Result<(), ContextError> {
        let kp = KeyPackage::mock(DID::from(member_did));
        self.manager.join_context(handle, kp).await
    }

    /// Joins a context by retrieving the Welcome from the `KeyExchange`.
    ///
    /// This is the Bob-side operation. It calls `crypto.join_from_welcome`
    /// which retrieves the Welcome and sender keys deposited by Alice.
    ///
    /// # Errors
    ///
    /// Propagates `ContextError` if no Welcome is available.
    pub fn join_from_welcome(&self, context_id: &[u8; 32]) -> Result<(), ContextError> {
        self.crypto.join_from_welcome(context_id)
    }

    /// Sends a message through `ContextManager` (encrypts with real crypto).
    ///
    /// The encrypted ciphertext is captured by the transport and can be
    /// retrieved via [`take_sent_ciphertexts`](Self::take_sent_ciphertexts).
    ///
    /// # Errors
    ///
    /// Propagates `ContextError` from `ContextManager`.
    pub async fn send_message(
        &self,
        handle: &ContextHandle,
        payload: &[u8],
    ) -> Result<(), ContextError> {
        self.manager
            .send_message(handle, &self.did, payload, None)
            .await
    }

    /// Takes all captured ciphertexts sent by this node.
    ///
    /// Returns `(context_id_bytes, ciphertext)` pairs and clears the buffer.
    pub fn take_sent_ciphertexts(&self) -> Vec<([u8; 32], Vec<u8>)> {
        let mut sent = self
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *sent)
    }

    /// Processes any pending MLS commits for this node in the given context.
    ///
    /// Must be called before `decrypt_message` if another member added a
    /// third party since this node last synced (the MLS epoch advances and
    /// this node needs to process the Commit to stay current).
    ///
    /// # Errors
    ///
    /// Propagates `ContextError` if commit processing fails.
    pub fn process_pending_commits(&self, context_id: &[u8; 32]) -> Result<(), ContextError> {
        self.crypto.process_pending_commits(context_id)
    }

    /// Decrypts a message using the crypto provider's extra `decrypt_message`.
    ///
    /// Automatically processes any pending MLS commits first so the group
    /// epoch is current.
    ///
    /// # Errors
    ///
    /// Propagates `ContextError` if MLS or sender key decryption fails.
    pub fn decrypt_message(
        &self,
        context_id: &[u8; 32],
        ciphertext: &[u8],
        sender_did: &str,
        epoch: u64,
        sequence: u64,
    ) -> Result<Vec<u8>, ContextError> {
        // Process any pending commits first to sync the MLS epoch.
        self.crypto.process_pending_commits(context_id)?;
        self.crypto
            .decrypt_message(context_id, ciphertext, sender_did, epoch, sequence)
    }

    /// Picks up any pending sender keys from the shared `KeyExchange`.
    ///
    /// Call this after another node has distributed its sender key so this
    /// node can decrypt messages from that sender.
    ///
    /// # Errors
    ///
    /// Propagates `ContextError` from the crypto provider.
    pub fn pickup_sender_keys(&self, context_id: &[u8; 32]) -> Result<(), ContextError> {
        self.crypto.pickup_sender_keys(context_id)
    }

    /// Drains events from the `ContextManager`.
    pub async fn drain_events(&self, context_id: &str) -> Vec<ContextEvent> {
        self.manager.drain_events(context_id).await
    }

    /// Returns the Merkle root of the event log for a context.
    ///
    /// # Errors
    ///
    /// Returns error if no event log exists for the context.
    pub fn merkle_root(&self, context_id: &[u8; 32]) -> Result<[u8; 32], ContextError> {
        self.event_log.event_log_merkle_root(context_id)
    }
}

// ---------------------------------------------------------------------------
// Arc wrapper newtypes — delegate trait methods to the inner Arc
// ---------------------------------------------------------------------------

/// Newtype wrapping `Arc<E2eCryptoProvider>` to implement `ContextCryptoProvider`.
struct ArcCryptoProvider(Arc<E2eCryptoProvider>);

impl ContextCryptoProvider for ArcCryptoProvider {
    fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
        self.0.validate_creator_identity()
    }
    fn create_mls_group(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.create_mls_group(id)
    }
    fn generate_sender_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.generate_sender_key(id)
    }
    fn init_broadcast_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.init_broadcast_key(id)
    }
    fn destroy_mls_group(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.destroy_mls_group(id)
    }
    fn destroy_sender_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.destroy_sender_key(id)
    }
    fn validate_key_package(&self, did: &str, kp: Option<&[u8]>) -> Result<(), ContextError> {
        self.0.validate_key_package(did, kp)
    }
    fn add_member(
        &self,
        id: &[u8; 32],
        did: &str,
        kp: Option<&[u8]>,
    ) -> Result<scp_core::context::AddMemberOutput, ContextError> {
        self.0.add_member(id, did, kp)
    }
    fn remove_member(&self, id: &[u8; 32], did: &str) -> Result<(), ContextError> {
        self.0.remove_member(id, did)
    }
    fn distribute_sender_key(&self, id: &[u8; 32], did: &str) -> Result<(), ContextError> {
        self.0.distribute_sender_key(id, did)
    }
    fn remove_member_sender_key(&self, id: &[u8; 32], did: &str) -> Result<(), ContextError> {
        self.0.remove_member_sender_key(id, did)
    }
    fn drain_pending_sender_key_messages(
        &self,
        id: &[u8; 32],
    ) -> Result<Vec<(String, Vec<u8>)>, ContextError> {
        self.0.drain_pending_sender_key_messages(id)
    }
    fn process_incoming_sender_key(
        &self,
        id: &[u8; 32],
        did: &str,
        msg: &[u8],
    ) -> Result<(), ContextError> {
        self.0.process_incoming_sender_key(id, did, msg)
    }
    fn handle_sender_key_request(
        &self,
        id: &[u8; 32],
        req: &[u8],
        pk: &[u8],
    ) -> Result<Option<Vec<u8>>, ContextError> {
        self.0.handle_sender_key_request(id, req, pk)
    }
    fn encrypt_message(
        &self,
        id: &[u8; 32],
        did: &str,
        payload: &[u8],
        epoch: u64,
        seq: u64,
    ) -> Result<Vec<u8>, ContextError> {
        self.0.encrypt_message(id, did, payload, epoch, seq)
    }
    fn advance_epoch(&self, id: &[u8; 32]) -> Result<(), ContextError> {
        self.0.advance_epoch(id)
    }
}

/// Newtype wrapping `Arc<MerkleEventLogProvider>` to implement `ContextEventLogProvider`.
struct ArcEventLogProvider(Arc<MerkleEventLogProvider>);

impl ContextEventLogProvider for ArcEventLogProvider {
    fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.init_event_log(id)
    }
    fn append_event(&self, id: &[u8; 32], event: &str) -> Result<(), ContextCreationError> {
        self.0.append_event(id, event)
    }
    fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.destroy_event_log(id)
    }
    fn append_context_event(&self, id: &[u8; 32], event: &str) -> Result<(), ContextError> {
        self.0.append_context_event(id, event)
    }
    fn export_event_log_data(&self, id: &[u8; 32]) -> Result<Vec<u8>, ContextError> {
        self.0.export_event_log_data(id)
    }
    fn import_event_log_data(&self, id: &[u8; 32], data: &[u8]) -> Result<(), ContextError> {
        self.0.import_event_log_data(id, data)
    }
    fn event_log_merkle_root(&self, id: &[u8; 32]) -> Result<[u8; 32], ContextError> {
        self.0.event_log_merkle_root(id)
    }
    fn restore_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.restore_event_log(id)
    }
}
